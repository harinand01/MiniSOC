import json
import logging
import sys
from kafka import KafkaProducer
from apscheduler.schedulers.blocking import BlockingScheduler
import config
from events import generate_event

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

import time

def create_producer(retries=30, delay=3):

    for attempt in range(1, retries + 1):
        try:
            producer = KafkaProducer(
                bootstrap_servers=[config.KAFKA_BROKER],
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            logger.info("Connected to Kafka successfully.")
            return producer
        except Exception as e:
            logger.warning(f"Failed to connect to Kafka (attempt {attempt}/{retries}): {e}. Retrying in {delay}s...")
            time.sleep(delay)
    logger.error("Could not connect to Kafka after multiple retries. Exiting.")
    sys.exit(1)

producer = create_producer()


def produce_log():
    event = generate_event()
    try:
        producer.send(config.KAFKA_TOPIC, value=event)
        producer.flush()
        logger.info(f"Sent event: {event['event_type']} from {event['ip']} (failed attempts: {event.get('failed_attempts', 0)})")
    except Exception as e:
        logger.error(f"Failed to send message: {e}")

if __name__ == "__main__":
    logger.info(f"Starting log generator. Pushing to {config.KAFKA_BROKER} topic: {config.KAFKA_TOPIC}")
    scheduler = BlockingScheduler()
    # Run every 500 milliseconds (0.5 seconds)
    scheduler.add_job(produce_log, 'interval', seconds=0.5)
    
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Log generator stopped.")
