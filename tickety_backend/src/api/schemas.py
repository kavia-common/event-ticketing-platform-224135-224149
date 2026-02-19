from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field


class TokenPair(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field("bearer", description="Token type (Bearer)")


class Message(BaseModel):
    message: str


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    first_name: str | None = None
    last_name: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class UserPublic(BaseModel):
    id: str
    email: EmailStr
    first_name: str | None = None
    last_name: str | None = None
    is_email_verified: bool
    created_at: datetime


class VenueCreate(BaseModel):
    name: str
    description: str | None = None
    address_line1: str | None = None
    address_line2: str | None = None
    city: str | None = None
    state: str | None = None
    postal_code: str | None = None
    country: str | None = None
    timezone: str = "UTC"


class Venue(VenueCreate):
    id: str
    created_at: datetime
    updated_at: datetime


class SeatMapCreate(BaseModel):
    venue_id: str
    name: str
    layout_json: dict[str, Any] | None = None


class SeatMap(SeatMapCreate):
    id: str
    created_at: datetime


class SeatCreate(BaseModel):
    seat_map_id: str
    section: str | None = None
    row_label: str | None = None
    seat_number: str
    label: str | None = None
    is_accessible: bool = False
    is_obstructed_view: bool = False
    x: float | None = None
    y: float | None = None
    metadata: dict[str, Any] | None = None


class Seat(SeatCreate):
    id: str
    created_at: datetime


class EventCreate(BaseModel):
    venue_id: str
    seat_map_id: str | None = None
    title: str
    description: str | None = None
    category: str | None = None
    status: Literal["draft", "published", "cancelled"] = "draft"
    start_at: datetime
    end_at: datetime | None = None
    doors_open_at: datetime | None = None
    poster_image_url: str | None = None


class Event(EventCreate):
    id: str
    created_by: str | None = None
    created_at: datetime
    updated_at: datetime


class TicketTypeCreate(BaseModel):
    event_id: str
    name: str
    description: str | None = None
    is_seated: bool = False
    inventory_total: int | None = Field(
        default=None, description="GA inventory. NULL for unlimited/seat-based."
    )
    sales_start_at: datetime | None = None
    sales_end_at: datetime | None = None


class TicketType(TicketTypeCreate):
    id: str
    inventory_sold: int
    created_at: datetime
    updated_at: datetime


class PricingTierCreate(BaseModel):
    ticket_type_id: str
    name: str
    currency: str = Field("USD", min_length=3, max_length=3)
    price_cents: int = Field(..., ge=0)
    fee_cents: int = Field(0, ge=0)
    start_at: datetime | None = None
    end_at: datetime | None = None
    is_active: bool = True


class PricingTier(PricingTierCreate):
    id: str
    created_at: datetime


class CartItemAdd(BaseModel):
    event_id: str
    ticket_type_id: str
    pricing_tier_id: str | None = None
    seat_id: str | None = None
    quantity: int = Field(1, gt=0)


class CartItem(BaseModel):
    id: str
    cart_id: str
    event_id: str
    ticket_type_id: str
    pricing_tier_id: str | None
    seat_id: str | None
    quantity: int
    unit_price_cents: int
    unit_fee_cents: int
    currency: str
    created_at: datetime


class Cart(BaseModel):
    id: str
    user_id: str | None
    status: str
    currency: str
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime
    items: list[CartItem] = []


class ApplyPromoRequest(BaseModel):
    code: str


class CheckoutRequest(BaseModel):
    cart_id: str
    promo_code: str | None = None


class Order(BaseModel):
    id: str
    user_id: str | None
    status: str
    currency: str
    subtotal_cents: int
    fees_cents: int
    discount_cents: int
    tax_cents: int
    total_cents: int
    promo_code_id: str | None
    cart_id: str | None
    created_at: datetime
    updated_at: datetime


class PaymentIntentResponse(BaseModel):
    order_id: str
    payment_id: str
    stripe_payment_intent_id: str
    client_secret: str


class RefundRequest(BaseModel):
    payment_id: str
    amount_cents: int = Field(..., ge=1)
    reason: str | None = None


class PromoCreate(BaseModel):
    code: str
    description: str | None = None
    discount_type: Literal["percent", "amount"]
    discount_value: int = Field(..., ge=0)
    currency: str = Field("USD", min_length=3, max_length=3)
    max_redemptions: int | None = None
    per_user_limit: int | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    is_active: bool = True
    event_ids: list[str] | None = Field(
        default=None, description="Optional scoping to events"
    )


class Promo(PromoCreate):
    id: str
    redemption_count: int
    created_at: datetime
    created_by: str | None = None


class AnalyticsIngest(BaseModel):
    event_name: str
    properties: dict[str, Any] | None = None
    anonymous_id: str | None = None
    occurred_at: datetime | None = None


class AnalyticsSummary(BaseModel):
    from_at: datetime
    to_at: datetime
    by_event_name: dict[str, int]
