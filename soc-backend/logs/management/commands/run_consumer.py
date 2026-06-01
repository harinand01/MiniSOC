"""
Django management command to run the Kafka consumer.
Usage: python manage.py run_consumer
"""

import logging
import os
import sys

from django.core.management.base import BaseCommand

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Start the Kafka consumer — reads soc-logs topic and saves to DB"

    def add_arguments(self, parser):
        parser.add_argument(
            "--broker",
            type=str,
            default=os.getenv("KAFKA_BROKER", "localhost:9092"),
            help="Kafka broker address (default: localhost:9092)",
        )
        parser.add_argument(
            "--topic",
            type=str,
            default=os.getenv("KAFKA_TOPIC", "soc-logs"),
            help="Kafka topic to consume (default: soc-logs)",
        )

    def handle(self, *args, **options):
        broker = options["broker"]
        topic  = options["topic"]

        # Override env vars so kafka_consumer picks them up
        os.environ["KAFKA_BROKER"] = broker
        os.environ["KAFKA_TOPIC"]  = topic

        self.stdout.write(self.style.SUCCESS(
            f"Starting Kafka consumer\n"
            f"  Broker : {broker}\n"
            f"  Topic  : {topic}\n"
            f"Press Ctrl+C to stop.\n"
        ))

        # Configure console logging so progress is visible
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)-8s %(message)s",
            datefmt="%H:%M:%S",
            stream=sys.stdout,
        )

        # Run the consumer (blocking)
        from logs.kafka_consumer import run_consumer
        run_consumer()
