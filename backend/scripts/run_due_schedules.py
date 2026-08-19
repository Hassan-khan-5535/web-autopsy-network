"""Run the bounded Extension 12 schedule checker from an external periodic trigger."""

from app.core.database import SessionLocal
from app.services.continuous import RecurringScheduleService


def main() -> None:
    db = SessionLocal()
    try:
        print(RecurringScheduleService(db).run_due())
    finally:
        db.close()


if __name__ == "__main__":
    main()
