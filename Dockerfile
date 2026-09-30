# receiptchain — tamper-evident run receipts for scheduled jobs
#
# Build:  docker build -t wallydk24/receiptchain .
# Emit:   docker run --rm -e RECEIPTCHAIN_KEY=$KEY -v receipts:/data \
#           wallydk24/receiptchain emit --log /data/receipts.jsonl \
#           --job-id nightly --started-at ... --finished-at ... --status ok
# Verify: docker run --rm -e RECEIPTCHAIN_KEY=$KEY -v receipts:/data \
#           wallydk24/receiptchain verify --log /data/receipts.jsonl
#
# The HMAC key is NEVER baked into the image — pass it at runtime via
# RECEIPTCHAIN_KEY (or mount a key file and use --key-file). Keep the
# receipt log on a volume so it survives the container.

FROM python:3.12-alpine

WORKDIR /app
COPY receiptchain.py ./
RUN adduser -D rc && chown -R rc:rc /app
USER rc

VOLUME ["/data"]
ENTRYPOINT ["python3", "/app/receiptchain.py"]
CMD ["--help"]
