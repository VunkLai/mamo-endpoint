import uuid
from typing import Any

from django.core.management.base import BaseCommand

from control.models import Device


class Command(BaseCommand):
    def handle(self, *args: Any, **options: Any) -> str:
        private_key, public_key = Device.objects.generate_keys()
        device, _ = Device.objects.get_or_create(
            defaults={
                "uuid": uuid.uuid1(),
                "private_key": private_key,
                "public_key": public_key,
            }
        )
        device.update_ip()

        return "done"
