"""Mock Customer model with PII fields.

This module intentionally contains realistic PII data structures used by
customer_service.py. The planted leaks live in the service layer, not here.
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Customer:
    """Represents a bank customer record."""
    customer_id: str
    name: str
    ic_number: str          # Malaysian NRIC, e.g. "900101-01-1234"
    email: str
    phone: str
    account_number: str     # 14-digit bank account number
    credit_card: Optional[str] = None   # 16-digit PAN (optional)

    def __repr__(self) -> str:
        # __repr__ intentionally exposes all fields — this is what makes
        # logger.info(f"Processing {customer}") a leak vector.
        return (
            f"Customer(id={self.customer_id}, name={self.name}, "
            f"ic={self.ic_number}, email={self.email}, "
            f"phone={self.phone}, account={self.account_number})"
        )


# ---------------------------------------------------------------------------
# Sample in-memory "database"
# ---------------------------------------------------------------------------

CUSTOMERS: dict[str, Customer] = {
    "C001": Customer(
        customer_id="C001",
        name="Ahmad Bin Abdullah",
        ic_number="900101-01-1234",
        email="ahmad@example.com",
        phone="012-3456789",
        account_number="12345678901234",
        credit_card="4532015112830366",
    ),
    "C002": Customer(
        customer_id="C002",
        name="Siti Binti Hassan",
        ic_number="850615-03-5678",
        email="siti@example.com",
        phone="011-98765432",
        account_number="98765432109876",
        credit_card=None,
    ),
}
