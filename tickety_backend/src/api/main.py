from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import stripe
from fastapi import (
    Body,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    Response,
    Security,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.core.db import get_db
from src.api.core.security import (
    create_access_token,
    create_refresh_token,
    get_current_user,
    hash_password,
    require_role,
    verify_password,
)
from src.api.core.settings import get_settings
from src.api.schemas import (
    AnalyticsIngest,
    AnalyticsSummary,
    ApplyPromoRequest,
    Cart,
    CartItem,
    CartItemAdd,
    CheckoutRequest,
    Event,
    EventCreate,
    LoginRequest,
    Message,
    PaymentIntentResponse,
    PricingTier,
    PricingTierCreate,
    Promo,
    PromoCreate,
    RefreshRequest,
    Seat,
    SeatCreate,
    SeatMap,
    SeatMapCreate,
    SignupRequest,
    TicketType,
    TicketTypeCreate,
    TokenPair,
    UserPublic,
    Venue,
    VenueCreate,
)
from src.api.services.utils import generate_qr_token, qr_png_data_uri, send_email

openapi_tags = [
    {"name": "health", "description": "Health checks and meta documentation."},
    {"name": "auth", "description": "User authentication and JWT token endpoints."},
    {"name": "venues", "description": "Venue and seating topology management."},
    {"name": "events", "description": "Event catalog and pricing CRUD."},
    {"name": "cart", "description": "Cart operations: add/remove items, apply promo."},
    {"name": "orders", "description": "Checkout, order history, ticket issuance."},
    {"name": "payments", "description": "Stripe payment intents, webhooks, refunds."},
    {"name": "promos", "description": "Promo code CRUD and validation."},
    {"name": "analytics", "description": "Analytics ingestion and basic reporting."},
]

app = FastAPI(
    title="Tickety Backend API",
    description=(
        "Tickety is an event ticketing backend with JWT auth + RBAC, cart/checkout, "
        "Stripe payments, ticket issuance (QR token), promos, refunds, and analytics."
    ),
    version="1.0.0",
    openapi_tags=openapi_tags,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # frontend config controls base URL; for template allow all
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _now() -> datetime:
    return datetime.now(UTC)


async def _audit(
    db: AsyncSession,
    actor_user_id: str | None,
    action: str,
    entity_type: str | None = None,
    entity_id: str | None = None,
    request: Request | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    await db.execute(
        text(
            """
            INSERT INTO audit_log (actor_user_id, action, entity_type, entity_id, ip_address, user_agent, details)
            VALUES (:actor_user_id, :action, :entity_type, :entity_id, :ip, :ua, :details::jsonb)
            """
        ),
        {
            "actor_user_id": actor_user_id,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "ip": (request.client.host if request and request.client else None),
            "ua": (request.headers.get("user-agent") if request else None),
            "details": json.dumps(details or {}),
        },
    )


async def _get_user_roles(db: AsyncSession, user_id: str) -> list[str]:
    res = await db.execute(
        text(
            """
            SELECT r.name
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = :user_id
            """
        ),
        {"user_id": user_id},
    )
    return [r[0] for r in res.all()]


async def _load_cart(db: AsyncSession, cart_id: str) -> Cart:
    cart_res = await db.execute(
        text("SELECT * FROM carts WHERE id = :id"),
        {"id": cart_id},
    )
    cart_row = cart_res.mappings().first()
    if not cart_row:
        raise HTTPException(status_code=404, detail="Cart not found")

    items_res = await db.execute(
        text("SELECT * FROM cart_items WHERE cart_id = :id ORDER BY created_at ASC"),
        {"id": cart_id},
    )
    items = [CartItem(**dict(r)) for r in items_res.mappings().all()]
    return Cart(**dict(cart_row), items=items)


async def _resolve_item_pricing(
    db: AsyncSession, ticket_type_id: str, pricing_tier_id: str | None, seat_id: str | None
) -> tuple[int, int, str]:
    # Seat-specific overrides take precedence (if seat_id present and configured).
    if seat_id:
        res = await db.execute(
            text(
                """
                SELECT sp.price_cents, sp.fee_cents, sp.currency
                FROM seat_pricing sp
                JOIN ticket_types tt ON tt.event_id = sp.event_id
                WHERE tt.id = :ticket_type_id AND sp.seat_id = :seat_id
                """
            ),
            {"ticket_type_id": ticket_type_id, "seat_id": seat_id},
        )
        row = res.mappings().first()
        if row:
            return int(row["price_cents"]), int(row["fee_cents"]), row["currency"]

    if pricing_tier_id:
        res = await db.execute(
            text(
                """
                SELECT currency, price_cents, fee_cents
                FROM pricing_tiers
                WHERE id = :id AND is_active = TRUE
                """
            ),
            {"id": pricing_tier_id},
        )
        row = res.mappings().first()
        if not row:
            raise HTTPException(status_code=400, detail="Invalid pricing tier")
        return int(row["price_cents"]), int(row["fee_cents"]), row["currency"]

    # Fallback: pick any active tier for ticket type, prefer newest.
    res = await db.execute(
        text(
            """
            SELECT currency, price_cents, fee_cents
            FROM pricing_tiers
            WHERE ticket_type_id = :ttid AND is_active = TRUE
            ORDER BY created_at DESC
            LIMIT 1
            """
        ),
        {"ttid": ticket_type_id},
    )
    row = res.mappings().first()
    if not row:
        raise HTTPException(status_code=400, detail="No active pricing tier for ticket type")
    return int(row["price_cents"]), int(row["fee_cents"]), row["currency"]


async def _validate_promo(
    db: AsyncSession, user_id: str | None, code: str, event_ids: list[str]
) -> tuple[str, int]:
    res = await db.execute(
        text(
            """
            SELECT *
            FROM promo_codes
            WHERE code = :code
            """
        ),
        {"code": code},
    )
    promo = res.mappings().first()
    if not promo or not promo["is_active"]:
        raise HTTPException(status_code=400, detail="Invalid promo code")

    now = _now()
    if promo["starts_at"] and promo["starts_at"] > now:
        raise HTTPException(status_code=400, detail="Promo code not started")
    if promo["ends_at"] and promo["ends_at"] < now:
        raise HTTPException(status_code=400, detail="Promo code expired")
    if promo["max_redemptions"] is not None and promo["redemption_count"] >= promo["max_redemptions"]:
        raise HTTPException(status_code=400, detail="Promo code fully redeemed")

    # Event scoping (if exists, must match at least one event).
    scope_res = await db.execute(
        text(
            """
            SELECT event_id FROM promo_code_event_scopes
            WHERE promo_code_id = :pid
            """
        ),
        {"pid": promo["id"]},
    )
    scoped = [r[0] for r in scope_res.all()]
    if scoped:
        if not any(eid in set(scoped) for eid in event_ids):
            raise HTTPException(status_code=400, detail="Promo code not valid for these events")

    # Per-user limit
    if user_id and promo["per_user_limit"] is not None:
        ures = await db.execute(
            text(
                """
                SELECT count(*) AS cnt
                FROM promo_redemptions
                WHERE promo_code_id = :pid AND user_id = :uid
                """
            ),
            {"pid": promo["id"], "uid": user_id},
        )
        if int(ures.mappings().first()["cnt"]) >= int(promo["per_user_limit"]):
            raise HTTPException(status_code=400, detail="Promo code per-user limit reached")

    return str(promo["id"]), int(promo["discount_value"])


async def _compute_cart_totals(
    db: AsyncSession, cart: Cart, promo_code: str | None, user_id: str | None
) -> dict[str, int]:
    subtotal = sum(i.unit_price_cents * i.quantity for i in cart.items)
    fees = sum(i.unit_fee_cents * i.quantity for i in cart.items)
    discount = 0
    promo_id: str | None = None

    if promo_code:
        promo_id, discount_value = await _validate_promo(
            db,
            user_id=user_id,
            code=promo_code,
            event_ids=list({i.event_id for i in cart.items}),
        )
        # Apply percent or amount based on DB row
        pres = await db.execute(
            text("SELECT discount_type FROM promo_codes WHERE id = :id"),
            {"id": promo_id},
        )
        dtype = pres.mappings().first()["discount_type"]
        if dtype == "percent":
            discount = int((subtotal * discount_value) // 100)
        else:
            discount = min(subtotal, int(discount_value))

    total = max(0, subtotal + fees - discount)
    return {
        "subtotal_cents": subtotal,
        "fees_cents": fees,
        "discount_cents": discount,
        "tax_cents": 0,
        "total_cents": total,
        "promo_code_id": promo_id or "",
    }


@app.get("/", tags=["health"], summary="Health check")
def health_check() -> dict[str, str]:
    """Health check endpoint for container orchestration."""
    return {"message": "Healthy"}


@app.get(
    "/docs/webhooks",
    tags=["health"],
    summary="Webhook usage help",
    description="Explains Stripe webhook endpoint and required headers.",
)
def webhook_docs() -> dict[str, Any]:
    """Return documentation for Stripe webhooks usage."""
    return {
        "stripe": {
            "webhook_endpoint": "/payments/stripe/webhook",
            "headers": {"Stripe-Signature": "t=...,v1=..."},
            "events_used": ["payment_intent.succeeded", "payment_intent.payment_failed"],
        }
    }


# --------------------
# AUTH
# --------------------
@app.post(
    "/auth/signup",
    response_model=UserPublic,
    tags=["auth"],
    summary="Create an account",
)
async def signup(payload: SignupRequest, db: AsyncSession = Depends(get_db)) -> UserPublic:
    """Create a new user and assign the default 'user' role."""
    existing = await db.execute(
        text("SELECT id FROM users WHERE email = :email"), {"email": payload.email}
    )
    if existing.first():
        raise HTTPException(status_code=409, detail="Email already registered")

    password_hash = hash_password(payload.password)
    res = await db.execute(
        text(
            """
            INSERT INTO users (email, password_hash, first_name, last_name, is_active, is_email_verified)
            VALUES (:email, :ph, :fn, :ln, TRUE, TRUE)
            RETURNING id, email, first_name, last_name, is_email_verified, created_at
            """
        ),
        {"email": payload.email, "ph": password_hash, "fn": payload.first_name, "ln": payload.last_name},
    )
    user = res.mappings().first()
    # Assign role user
    await db.execute(
        text(
            """
            INSERT INTO user_roles (user_id, role_id)
            SELECT :uid, r.id FROM roles r WHERE r.name = 'user'
            ON CONFLICT DO NOTHING
            """
        ),
        {"uid": user["id"]},
    )
    await db.commit()
    return UserPublic(**dict(user))


@app.post(
    "/auth/login",
    response_model=TokenPair,
    tags=["auth"],
    summary="Login and get JWT tokens",
)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenPair:
    """Validate credentials and return access+refresh tokens."""
    res = await db.execute(
        text("SELECT id, password_hash FROM users WHERE email = :email"),
        {"email": payload.email},
    )
    row = res.mappings().first()
    if not row or not row["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not verify_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    access = create_access_token(str(row["id"]))
    refresh = create_refresh_token(str(row["id"]))
    return TokenPair(access_token=access, refresh_token=refresh)


@app.post(
    "/auth/refresh",
    response_model=TokenPair,
    tags=["auth"],
    summary="Refresh JWT access token",
)
async def refresh(payload: RefreshRequest, db: AsyncSession = Depends(get_db)) -> TokenPair:
    """Exchange refresh token for a new access token."""
    settings = get_settings()
    try:
        decoded = jwt.decode(
            payload.refresh_token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if decoded.get("typ") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_id = decoded.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token subject")

    # Ensure user exists/active
    ures = await db.execute(
        text("SELECT id, is_active FROM users WHERE id = :id"), {"id": user_id}
    )
    u = ures.mappings().first()
    if not u or not u["is_active"]:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    return TokenPair(
        access_token=create_access_token(user_id),
        refresh_token=create_refresh_token(user_id),
    )


@app.get(
    "/auth/me",
    response_model=UserPublic,
    tags=["auth"],
    summary="Get current user",
)
async def me(current_user: dict[str, Any] = Depends(get_current_user)) -> UserPublic:
    """Return current user's public profile."""
    return UserPublic(**current_user)


# --------------------
# VENUES / SEATS
# --------------------
@app.post(
    "/venues",
    response_model=Venue,
    tags=["venues"],
    summary="Create venue (admin)",
)
async def create_venue(
    payload: VenueCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin_user: dict[str, Any] = Depends(lambda: require_role("admin")),
) -> Venue:
    """Create a venue (admin only)."""
    res = await db.execute(
        text(
            """
            INSERT INTO venues (name, description, address_line1, address_line2, city, state, postal_code, country, timezone)
            VALUES (:name, :description, :a1, :a2, :city, :state, :pc, :country, :tz)
            RETURNING *
            """
        ),
        {
            "name": payload.name,
            "description": payload.description,
            "a1": payload.address_line1,
            "a2": payload.address_line2,
            "city": payload.city,
            "state": payload.state,
            "pc": payload.postal_code,
            "country": payload.country,
            "tz": payload.timezone,
        },
    )
    venue = res.mappings().first()
    await _audit(db, admin_user["id"], "venue.create", "venue", str(venue["id"]), request)
    await db.commit()
    return Venue(**dict(venue))


@app.get(
    "/venues",
    response_model=list[Venue],
    tags=["venues"],
    summary="List venues",
)
async def list_venues(db: AsyncSession = Depends(get_db)) -> list[Venue]:
    """List venues."""
    res = await db.execute(text("SELECT * FROM venues ORDER BY created_at DESC"))
    return [Venue(**dict(r)) for r in res.mappings().all()]


@app.get(
    "/venues/{venue_id}",
    response_model=Venue,
    tags=["venues"],
    summary="Get venue",
)
async def get_venue(venue_id: str, db: AsyncSession = Depends(get_db)) -> Venue:
    """Get a venue by id."""
    res = await db.execute(text("SELECT * FROM venues WHERE id = :id"), {"id": venue_id})
    row = res.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Venue not found")
    return Venue(**dict(row))


@app.post(
    "/seat-maps",
    response_model=SeatMap,
    tags=["venues"],
    summary="Create seat map (admin)",
)
async def create_seat_map(
    payload: SeatMapCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin_user: dict[str, Any] = Depends(lambda: require_role("admin")),
) -> SeatMap:
    """Create seat map for a venue (admin only)."""
    res = await db.execute(
        text(
            """
            INSERT INTO seat_maps (venue_id, name, layout_json)
            VALUES (:vid, :name, :layout::jsonb)
            RETURNING *
            """
        ),
        {"vid": payload.venue_id, "name": payload.name, "layout": json.dumps(payload.layout_json)},
    )
    sm = res.mappings().first()
    await _audit(db, admin_user["id"], "seat_map.create", "seat_map", str(sm["id"]), request)
    await db.commit()
    return SeatMap(**dict(sm))


@app.get(
    "/venues/{venue_id}/seat-maps",
    response_model=list[SeatMap],
    tags=["venues"],
    summary="List seat maps for a venue",
)
async def list_seat_maps(venue_id: str, db: AsyncSession = Depends(get_db)) -> list[SeatMap]:
    """List seat maps for a venue."""
    res = await db.execute(
        text("SELECT * FROM seat_maps WHERE venue_id = :id ORDER BY created_at DESC"),
        {"id": venue_id},
    )
    return [SeatMap(**dict(r)) for r in res.mappings().all()]


@app.post(
    "/seats",
    response_model=Seat,
    tags=["venues"],
    summary="Create seat (admin)",
)
async def create_seat(
    payload: SeatCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin_user: dict[str, Any] = Depends(lambda: require_role("admin")),
) -> Seat:
    """Create a seat in a seat map (admin only)."""
    res = await db.execute(
        text(
            """
            INSERT INTO seats (seat_map_id, section, row_label, seat_number, label, is_accessible, is_obstructed_view, x, y, metadata)
            VALUES (:smid, :section, :row, :num, :label, :acc, :obs, :x, :y, :meta::jsonb)
            RETURNING *
            """
        ),
        {
            "smid": payload.seat_map_id,
            "section": payload.section,
            "row": payload.row_label,
            "num": payload.seat_number,
            "label": payload.label,
            "acc": payload.is_accessible,
            "obs": payload.is_obstructed_view,
            "x": payload.x,
            "y": payload.y,
            "meta": json.dumps(payload.metadata),
        },
    )
    seat = res.mappings().first()
    await _audit(db, admin_user["id"], "seat.create", "seat", str(seat["id"]), request)
    await db.commit()
    return Seat(**dict(seat))


@app.get(
    "/seat-maps/{seat_map_id}/seats",
    response_model=list[Seat],
    tags=["venues"],
    summary="List seats in seat map",
)
async def list_seats(seat_map_id: str, db: AsyncSession = Depends(get_db)) -> list[Seat]:
    """List seats for seat map."""
    res = await db.execute(
        text("SELECT * FROM seats WHERE seat_map_id = :id ORDER BY section, row_label, seat_number"),
        {"id": seat_map_id},
    )
    return [Seat(**dict(r)) for r in res.mappings().all()]


# --------------------
# EVENTS + PRICING
# --------------------
@app.post(
    "/events",
    response_model=Event,
    tags=["events"],
    summary="Create event (admin)",
)
async def create_event(
    payload: EventCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin_user: dict[str, Any] = Depends(lambda: require_role("admin")),
) -> Event:
    """Create event (admin only)."""
    res = await db.execute(
        text(
            """
            INSERT INTO events (venue_id, seat_map_id, title, description, category, status, start_at, end_at, doors_open_at, poster_image_url, created_by)
            VALUES (:vid, :smid, :title, :desc, :cat, :status, :start, :end, :doors, :poster, :created_by)
            RETURNING *
            """
        ),
        {
            "vid": payload.venue_id,
            "smid": payload.seat_map_id,
            "title": payload.title,
            "desc": payload.description,
            "cat": payload.category,
            "status": payload.status,
            "start": payload.start_at,
            "end": payload.end_at,
            "doors": payload.doors_open_at,
            "poster": payload.poster_image_url,
            "created_by": admin_user["id"],
        },
    )
    ev = res.mappings().first()
    await _audit(db, admin_user["id"], "event.create", "event", str(ev["id"]), request)
    await db.commit()
    return Event(**dict(ev))


@app.get(
    "/events",
    response_model=list[Event],
    tags=["events"],
    summary="List events",
)
async def list_events(
    status_filter: str | None = None,
    q: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> list[Event]:
    """List events. Optional filters: status and text query."""
    where = []
    params: dict[str, Any] = {}
    if status_filter:
        where.append("status = :status")
        params["status"] = status_filter
    if q:
        where.append("(title ILIKE :q OR description ILIKE :q)")
        params["q"] = f"%{q}%"
    sql = "SELECT * FROM events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY start_at ASC"
    res = await db.execute(text(sql), params)
    return [Event(**dict(r)) for r in res.mappings().all()]


@app.get(
    "/events/{event_id}",
    response_model=Event,
    tags=["events"],
    summary="Get event",
)
async def get_event(event_id: str, db: AsyncSession = Depends(get_db)) -> Event:
    """Get event by id."""
    res = await db.execute(text("SELECT * FROM events WHERE id = :id"), {"id": event_id})
    row = res.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")
    return Event(**dict(row))


@app.post(
    "/ticket-types",
    response_model=TicketType,
    tags=["events"],
    summary="Create ticket type (admin)",
)
async def create_ticket_type(
    payload: TicketTypeCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin_user: dict[str, Any] = Depends(lambda: require_role("admin")),
) -> TicketType:
    """Create a ticket type for an event (admin only)."""
    res = await db.execute(
        text(
            """
            INSERT INTO ticket_types (event_id, name, description, is_seated, inventory_total, sales_start_at, sales_end_at)
            VALUES (:eid, :name, :desc, :seated, :inv, :ss, :se)
            RETURNING *
            """
        ),
        {
            "eid": payload.event_id,
            "name": payload.name,
            "desc": payload.description,
            "seated": payload.is_seated,
            "inv": payload.inventory_total,
            "ss": payload.sales_start_at,
            "se": payload.sales_end_at,
        },
    )
    tt = res.mappings().first()
    await _audit(db, admin_user["id"], "ticket_type.create", "ticket_type", str(tt["id"]), request)
    await db.commit()
    return TicketType(**dict(tt))


@app.get(
    "/events/{event_id}/ticket-types",
    response_model=list[TicketType],
    tags=["events"],
    summary="List ticket types for event",
)
async def list_ticket_types(event_id: str, db: AsyncSession = Depends(get_db)) -> list[TicketType]:
    """List ticket types for event."""
    res = await db.execute(
        text("SELECT * FROM ticket_types WHERE event_id = :id ORDER BY created_at ASC"),
        {"id": event_id},
    )
    return [TicketType(**dict(r)) for r in res.mappings().all()]


@app.post(
    "/pricing-tiers",
    response_model=PricingTier,
    tags=["events"],
    summary="Create pricing tier (admin)",
)
async def create_pricing_tier(
    payload: PricingTierCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin_user: dict[str, Any] = Depends(lambda: require_role("admin")),
) -> PricingTier:
    """Create pricing tier for a ticket type (admin only)."""
    res = await db.execute(
        text(
            """
            INSERT INTO pricing_tiers (ticket_type_id, name, currency, price_cents, fee_cents, start_at, end_at, is_active)
            VALUES (:ttid, :name, :cur, :price, :fee, :start, :end, :active)
            RETURNING *
            """
        ),
        {
            "ttid": payload.ticket_type_id,
            "name": payload.name,
            "cur": payload.currency,
            "price": payload.price_cents,
            "fee": payload.fee_cents,
            "start": payload.start_at,
            "end": payload.end_at,
            "active": payload.is_active,
        },
    )
    pt = res.mappings().first()
    await _audit(db, admin_user["id"], "pricing_tier.create", "pricing_tier", str(pt["id"]), request)
    await db.commit()
    return PricingTier(**dict(pt))


@app.get(
    "/ticket-types/{ticket_type_id}/pricing-tiers",
    response_model=list[PricingTier],
    tags=["events"],
    summary="List pricing tiers for ticket type",
)
async def list_pricing_tiers(ticket_type_id: str, db: AsyncSession = Depends(get_db)) -> list[PricingTier]:
    """List pricing tiers for a ticket type."""
    res = await db.execute(
        text("SELECT * FROM pricing_tiers WHERE ticket_type_id = :id ORDER BY created_at ASC"),
        {"id": ticket_type_id},
    )
    return [PricingTier(**dict(r)) for r in res.mappings().all()]


# --------------------
# CART
# --------------------
@app.post(
    "/cart",
    response_model=Cart,
    tags=["cart"],
    summary="Create cart",
)
async def create_cart(
    db: AsyncSession = Depends(get_db),
    current_user: dict[str, Any] | None = Security(lambda: None),  # placeholder for schema; not used
    authorization: str | None = Header(default=None),
) -> Cart:
    """Create a cart. If Authorization Bearer token provided, associates cart with user.

    This allows guest carts while enabling logged-in carts.
    """
    user_id: str | None = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        try:
            decoded = jwt.decode(
                token,
                get_settings().jwt_secret,
                algorithms=[get_settings().jwt_algorithm],
            )
            if decoded.get("typ") == "access" and decoded.get("sub"):
                user_id = decoded["sub"]
        except jwt.PyJWTError:
            user_id = None

    res = await db.execute(
        text(
            """
            INSERT INTO carts (user_id, status, currency, expires_at)
            VALUES (:uid, 'open', 'USD', :exp)
            RETURNING *
            """
        ),
        {"uid": user_id, "exp": _now() + timedelta(hours=2)},
    )
    cart = res.mappings().first()
    await db.commit()
    return Cart(**dict(cart), items=[])


@app.get(
    "/cart/{cart_id}",
    response_model=Cart,
    tags=["cart"],
    summary="Get cart",
)
async def get_cart(cart_id: str, db: AsyncSession = Depends(get_db)) -> Cart:
    """Get cart and items."""
    return await _load_cart(db, cart_id)


@app.post(
    "/cart/{cart_id}/items",
    response_model=Cart,
    tags=["cart"],
    summary="Add item to cart",
)
async def add_cart_item(cart_id: str, payload: CartItemAdd, db: AsyncSession = Depends(get_db)) -> Cart:
    """Add a ticket selection to a cart, with seat optional."""
    cart = await _load_cart(db, cart_id)
    if cart.status != "open":
        raise HTTPException(status_code=400, detail="Cart not open")

    # Validate ticket type + event match
    ttr = await db.execute(
        text("SELECT event_id, is_seated FROM ticket_types WHERE id = :id"),
        {"id": payload.ticket_type_id},
    )
    tt = ttr.mappings().first()
    if not tt or str(tt["event_id"]) != payload.event_id:
        raise HTTPException(status_code=400, detail="Invalid ticket type for event")

    if tt["is_seated"] and not payload.seat_id:
        raise HTTPException(status_code=400, detail="Seat required for seated ticket type")

    unit_price, unit_fee, currency = await _resolve_item_pricing(
        db,
        ticket_type_id=payload.ticket_type_id,
        pricing_tier_id=payload.pricing_tier_id,
        seat_id=payload.seat_id,
    )

    # For seated: enforce seat not already in paid/held orders by simple check:
    if payload.seat_id:
        seat_taken = await db.execute(
            text(
                """
                SELECT 1
                FROM tickets t
                JOIN orders o ON o.id = (SELECT oi.order_id FROM order_items oi WHERE oi.id = t.order_item_id)
                WHERE t.event_id = :eid AND t.seat_id = :sid AND o.status IN ('paid')
                LIMIT 1
                """
            ),
            {"eid": payload.event_id, "sid": payload.seat_id},
        )
        if seat_taken.first():
            raise HTTPException(status_code=409, detail="Seat already sold")

    await db.execute(
        text(
            """
            INSERT INTO cart_items (cart_id, event_id, ticket_type_id, pricing_tier_id, seat_id, quantity, unit_price_cents, unit_fee_cents, currency)
            VALUES (:cid, :eid, :ttid, :ptid, :sid, :qty, :price, :fee, :cur)
            ON CONFLICT (cart_id, seat_id) DO UPDATE
              SET quantity = cart_items.quantity + EXCLUDED.quantity
            """
        ),
        {
            "cid": cart_id,
            "eid": payload.event_id,
            "ttid": payload.ticket_type_id,
            "ptid": payload.pricing_tier_id,
            "sid": payload.seat_id,
            "qty": payload.quantity,
            "price": unit_price,
            "fee": unit_fee,
            "cur": currency,
        },
    )
    await db.execute(text("UPDATE carts SET updated_at = now() WHERE id = :id"), {"id": cart_id})
    await db.commit()
    return await _load_cart(db, cart_id)


@app.delete(
    "/cart/{cart_id}/items/{item_id}",
    response_model=Cart,
    tags=["cart"],
    summary="Remove item from cart",
)
async def remove_cart_item(cart_id: str, item_id: str, db: AsyncSession = Depends(get_db)) -> Cart:
    """Remove a cart item."""
    await db.execute(
        text("DELETE FROM cart_items WHERE id = :iid AND cart_id = :cid"),
        {"iid": item_id, "cid": cart_id},
    )
    await db.execute(text("UPDATE carts SET updated_at = now() WHERE id = :id"), {"id": cart_id})
    await db.commit()
    return await _load_cart(db, cart_id)


@app.post(
    "/cart/{cart_id}/apply-promo",
    response_model=Message,
    tags=["cart"],
    summary="Validate promo code for cart",
)
async def apply_promo(cart_id: str, payload: ApplyPromoRequest, db: AsyncSession = Depends(get_db)) -> Message:
    """Validate promo code against cart items (does not persist; used by frontend prior to checkout)."""
    cart = await _load_cart(db, cart_id)
    if not cart.items:
        raise HTTPException(status_code=400, detail="Cart empty")

    await _validate_promo(
        db,
        user_id=cart.user_id,
        code=payload.code,
        event_ids=list({i.event_id for i in cart.items}),
    )
    return Message(message="Promo code valid")


# --------------------
# CHECKOUT / ORDERS / TICKETS
# --------------------
@app.post(
    "/checkout",
    response_model=PaymentIntentResponse,
    tags=["orders", "payments"],
    summary="Create order and Stripe payment intent",
)
async def checkout(
    payload: CheckoutRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> PaymentIntentResponse:
    """Convert a cart into an order and create a Stripe PaymentIntent.

    The Stripe `client_secret` is returned to the frontend to confirm payment.
    """
    settings = get_settings()
    if not settings.stripe_secret_key:
        raise HTTPException(status_code=500, detail="Stripe not configured")
    stripe.api_key = settings.stripe_secret_key

    cart = await _load_cart(db, payload.cart_id)
    if cart.status != "open":
        raise HTTPException(status_code=400, detail="Cart not open")
    if not cart.items:
        raise HTTPException(status_code=400, detail="Cart empty")

    totals = await _compute_cart_totals(db, cart, payload.promo_code, cart.user_id)

    # Create order
    order_res = await db.execute(
        text(
            """
            INSERT INTO orders (user_id, status, currency, subtotal_cents, fees_cents, discount_cents, tax_cents, total_cents, promo_code_id, cart_id)
            VALUES (:uid, 'pending', :cur, :sub, :fees, :disc, :tax, :total, NULLIF(:promo,'')::uuid, :cart_id)
            RETURNING *
            """
        ),
        {
            "uid": cart.user_id,
            "cur": cart.currency,
            "sub": totals["subtotal_cents"],
            "fees": totals["fees_cents"],
            "disc": totals["discount_cents"],
            "tax": totals["tax_cents"],
            "total": totals["total_cents"],
            "promo": totals["promo_code_id"],
            "cart_id": cart.id,
        },
    )
    order = order_res.mappings().first()

    # Create order items mirroring cart items
    for it in cart.items:
        await db.execute(
            text(
                """
                INSERT INTO order_items (order_id, event_id, ticket_type_id, pricing_tier_id, seat_id, quantity, unit_price_cents, unit_fee_cents, currency)
                VALUES (:oid, :eid, :ttid, :ptid, :sid, :qty, :price, :fee, :cur)
                """
            ),
            {
                "oid": order["id"],
                "eid": it.event_id,
                "ttid": it.ticket_type_id,
                "ptid": it.pricing_tier_id,
                "sid": it.seat_id,
                "qty": it.quantity,
                "price": it.unit_price_cents,
                "fee": it.unit_fee_cents,
                "cur": it.currency,
            },
        )

    # Stripe PaymentIntent
    intent = stripe.PaymentIntent.create(
        amount=int(order["total_cents"]),
        currency=order["currency"].lower(),
        automatic_payment_methods={"enabled": True},
        metadata={
            "order_id": str(order["id"]),
        },
    )

    pay_res = await db.execute(
        text(
            """
            INSERT INTO payments (order_id, provider, provider_payment_intent_id, status, amount_cents, currency)
            VALUES (:oid, 'stripe', :pi, :status, :amount, :cur)
            RETURNING id
            """
        ),
        {
            "oid": order["id"],
            "pi": intent["id"],
            "status": intent["status"],
            "amount": order["total_cents"],
            "cur": order["currency"],
        },
    )
    payment_id = pay_res.mappings().first()["id"]

    # Mark cart converted
    await db.execute(
        text("UPDATE carts SET status = 'converted', updated_at = now() WHERE id = :id"),
        {"id": cart.id},
    )

    await _audit(db, cart.user_id, "checkout.create", "order", str(order["id"]), request)
    await db.commit()

    return PaymentIntentResponse(
        order_id=str(order["id"]),
        payment_id=str(payment_id),
        stripe_payment_intent_id=intent["id"],
        client_secret=intent["client_secret"],
    )


async def _issue_tickets_for_order(db: AsyncSession, order_id: str) -> None:
    # For each order_item, insert `quantity` tickets. For seated, seat_id will be set.
    oi_res = await db.execute(
        text("SELECT * FROM order_items WHERE order_id = :oid"),
        {"oid": order_id},
    )
    for oi in oi_res.mappings().all():
        qty = int(oi["quantity"])
        for _ in range(qty):
            await db.execute(
                text(
                    """
                    INSERT INTO tickets (order_item_id, event_id, user_id, seat_id, ticket_type_id, status, qr_code_token)
                    VALUES (:oiid, :eid, (SELECT user_id FROM orders WHERE id = :oid), :sid, :ttid, 'issued', :token)
                    """
                ),
                {
                    "oiid": oi["id"],
                    "eid": oi["event_id"],
                    "oid": order_id,
                    "sid": oi["seat_id"],
                    "ttid": oi["ticket_type_id"],
                    "token": generate_qr_token(),
                },
            )


@app.post(
    "/payments/stripe/webhook",
    tags=["payments"],
    summary="Stripe webhook handler",
    description="Handles Stripe payment_intent events to mark orders paid/failed and issue tickets.",
)
async def stripe_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Stripe webhook endpoint.

    Requires STRIPE_WEBHOOK_SECRET to validate the Stripe-Signature header.
    """
    settings = get_settings()
    if not settings.stripe_webhook_secret or not settings.stripe_secret_key:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    payload = await request.body()
    sig = request.headers.get("stripe-signature")
    if not sig:
        raise HTTPException(status_code=400, detail="Missing Stripe-Signature header")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig,
            secret=settings.stripe_webhook_secret,
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid signature")

    etype = event["type"]
    obj = event["data"]["object"]

    if etype in ("payment_intent.succeeded", "payment_intent.payment_failed"):
        pi_id = obj["id"]
        # Find payment & order
        pres = await db.execute(
            text(
                """
                SELECT p.id as payment_id, p.order_id, o.user_id, o.status as order_status
                FROM payments p
                JOIN orders o ON o.id = p.order_id
                WHERE p.provider = 'stripe' AND p.provider_payment_intent_id = :pi
                """
            ),
            {"pi": pi_id},
        )
        row = pres.mappings().first()
        if row:
            if etype == "payment_intent.succeeded":
                await db.execute(
                    text("UPDATE payments SET status = 'succeeded', captured_at = now() WHERE id = :id"),
                    {"id": row["payment_id"]},
                )
                await db.execute(
                    text("UPDATE orders SET status = 'paid', updated_at = now() WHERE id = :id"),
                    {"id": row["order_id"]},
                )
                # issue tickets if not already issued
                existing = await db.execute(
                    text(
                        """
                        SELECT 1 FROM tickets t
                        JOIN order_items oi ON oi.id = t.order_item_id
                        WHERE oi.order_id = :oid
                        LIMIT 1
                        """
                    ),
                    {"oid": row["order_id"]},
                )
                if existing.first() is None:
                    await _issue_tickets_for_order(db, str(row["order_id"]))
                # email confirmation (if user exists)
                if row["user_id"]:
                    ures = await db.execute(
                        text("SELECT email FROM users WHERE id = :id"),
                        {"id": row["user_id"]},
                    )
                    u = ures.mappings().first()
                    if u:
                        send_email(
                            to_email=u["email"],
                            subject="Your Tickety order is confirmed",
                            body_text=f"Thanks for your purchase! Order {row['order_id']} is confirmed.",
                        )
            else:
                await db.execute(
                    text("UPDATE payments SET status = 'failed' WHERE id = :id"),
                    {"id": row["payment_id"]},
                )
                await db.execute(
                    text("UPDATE orders SET status = 'failed', updated_at = now() WHERE id = :id"),
                    {"id": row["order_id"]},
                )
            await db.commit()

    return {"status": "ok"}


@app.get(
    "/orders/me",
    response_model=list[Order],
    tags=["orders"],
    summary="List my orders",
)
async def list_my_orders(
    db: AsyncSession = Depends(get_db),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> list[Order]:
    """List orders for current user."""
    res = await db.execute(
        text("SELECT * FROM orders WHERE user_id = :uid ORDER BY created_at DESC"),
        {"uid": current_user["id"]},
    )
    return [Order(**dict(r)) for r in res.mappings().all()]


@app.get(
    "/orders/{order_id}",
    response_model=Order,
    tags=["orders"],
    summary="Get an order (owner/admin)",
)
async def get_order(
    order_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> Order:
    """Get a single order if you own it or you are admin."""
    roles = await _get_user_roles(db, current_user["id"])
    res = await db.execute(text("SELECT * FROM orders WHERE id = :id"), {"id": order_id})
    row = res.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Order not found")
    if str(row["user_id"]) != current_user["id"] and "admin" not in roles:
        raise HTTPException(status_code=403, detail="Forbidden")
    return Order(**dict(row))


@app.get(
    "/orders/{order_id}/tickets",
    tags=["orders"],
    summary="List tickets for an order (owner/admin)",
)
async def list_order_tickets(
    order_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """List tickets for order; includes QR token + data URI QR for display."""
    roles = await _get_user_roles(db, current_user["id"])
    ores = await db.execute(text("SELECT user_id FROM orders WHERE id = :id"), {"id": order_id})
    o = ores.mappings().first()
    if not o:
        raise HTTPException(status_code=404, detail="Order not found")
    if str(o["user_id"]) != current_user["id"] and "admin" not in roles:
        raise HTTPException(status_code=403, detail="Forbidden")

    res = await db.execute(
        text(
            """
            SELECT t.id, t.event_id, t.seat_id, t.ticket_type_id, t.status, t.qr_code_token, t.issued_at
            FROM tickets t
            JOIN order_items oi ON oi.id = t.order_item_id
            WHERE oi.order_id = :oid
            ORDER BY t.issued_at ASC
            """
        ),
        {"oid": order_id},
    )
    out: list[dict[str, Any]] = []
    for r in res.mappings().all():
        token = r["qr_code_token"]
        out.append(
            {
                **dict(r),
                "qr_payload": token,
                "qr_png_data_uri": qr_png_data_uri(token),
            }
        )
    return out


# --------------------
# PROMO CODES (admin CRUD + public validate)
# --------------------
@app.post(
    "/promos",
    response_model=Promo,
    tags=["promos"],
    summary="Create promo code (admin)",
)
async def create_promo(
    payload: PromoCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin_user: dict[str, Any] = Depends(lambda: require_role("admin")),
) -> Promo:
    """Create promo code, optionally scoped to events."""
    res = await db.execute(
        text(
            """
            INSERT INTO promo_codes (code, description, discount_type, discount_value, currency, max_redemptions, per_user_limit, starts_at, ends_at, is_active, created_by)
            VALUES (:code, :desc, :dtype, :dval, :cur, :maxr, :pul, :starts, :ends, :active, :created_by)
            RETURNING *
            """
        ),
        {
            "code": payload.code,
            "desc": payload.description,
            "dtype": payload.discount_type,
            "dval": payload.discount_value,
            "cur": payload.currency,
            "maxr": payload.max_redemptions,
            "pul": payload.per_user_limit,
            "starts": payload.starts_at,
            "ends": payload.ends_at,
            "active": payload.is_active,
            "created_by": admin_user["id"],
        },
    )
    promo = res.mappings().first()

    if payload.event_ids:
        for eid in payload.event_ids:
            await db.execute(
                text(
                    """
                    INSERT INTO promo_code_event_scopes (promo_code_id, event_id)
                    VALUES (:pid, :eid)
                    ON CONFLICT DO NOTHING
                    """
                ),
                {"pid": promo["id"], "eid": eid},
            )

    await _audit(db, admin_user["id"], "promo.create", "promo_code", str(promo["id"]), request)
    await db.commit()

    return Promo(**dict(promo), event_ids=payload.event_ids)


@app.get(
    "/promos",
    response_model=list[Promo],
    tags=["promos"],
    summary="List promo codes (admin)",
)
async def list_promos(
    db: AsyncSession = Depends(get_db),
    admin_user: dict[str, Any] = Depends(lambda: require_role("admin")),
) -> list[Promo]:
    """List promo codes (admin only)."""
    res = await db.execute(text("SELECT * FROM promo_codes ORDER BY created_at DESC"))
    promos = []
    for p in res.mappings().all():
        scopes = await db.execute(
            text("SELECT event_id FROM promo_code_event_scopes WHERE promo_code_id = :id"),
            {"id": p["id"]},
        )
        promos.append(Promo(**dict(p), event_ids=[r[0] for r in scopes.all()]))
    return promos


@app.post(
    "/promos/validate",
    response_model=Message,
    tags=["promos"],
    summary="Validate promo code",
)
async def validate_promo_endpoint(
    payload: ApplyPromoRequest,
    db: AsyncSession = Depends(get_db),
) -> Message:
    """Validate promo code without a cart (frontend may use this during browsing)."""
    await _validate_promo(db, user_id=None, code=payload.code, event_ids=[])
    return Message(message="Promo code valid")


# --------------------
# REFUNDS (admin)
# --------------------
@app.post(
    "/refunds",
    tags=["payments"],
    summary="Create refund (admin)",
)
async def create_refund(
    payload: dict[str, Any] = Body(...),
    request: Request | None = None,
    db: AsyncSession = Depends(get_db),
    admin_user: dict[str, Any] = Depends(lambda: require_role("admin")),
) -> dict[str, Any]:
    """Refund a Stripe payment.

    Body:
      { "payment_id": "...", "amount_cents": 123, "reason": "..." }
    """
    settings = get_settings()
    if not settings.stripe_secret_key:
        raise HTTPException(status_code=500, detail="Stripe not configured")
    stripe.api_key = settings.stripe_secret_key

    payment_id = payload.get("payment_id")
    amount_cents = payload.get("amount_cents")
    reason = payload.get("reason")
    if not payment_id or not isinstance(amount_cents, int) or amount_cents <= 0:
        raise HTTPException(status_code=400, detail="Invalid refund request")

    pres = await db.execute(
        text("SELECT * FROM payments WHERE id = :id"),
        {"id": payment_id},
    )
    p = pres.mappings().first()
    if not p or p["provider"] != "stripe" or not p["provider_payment_intent_id"]:
        raise HTTPException(status_code=404, detail="Payment not found")

    # Create Stripe refund
    refund = stripe.Refund.create(
        payment_intent=p["provider_payment_intent_id"],
        amount=amount_cents,
        reason="requested_by_customer",
    )

    rres = await db.execute(
        text(
            """
            INSERT INTO refunds (payment_id, provider_refund_id, status, amount_cents, currency, reason, created_by)
            VALUES (:pid, :rid, :status, :amount, :cur, :reason, :created_by)
            RETURNING *
            """
        ),
        {
            "pid": p["id"],
            "rid": refund["id"],
            "status": refund["status"],
            "amount": amount_cents,
            "cur": p["currency"],
            "reason": reason,
            "created_by": admin_user["id"],
        },
    )
    row = rres.mappings().first()

    # Soft-update order status if full refund (simple heuristic)
    if amount_cents >= int(p["amount_cents"]):
        await db.execute(
            text("UPDATE orders SET status = 'refunded', updated_at = now() WHERE id = :id"),
            {"id": p["order_id"]},
        )
        await db.execute(
            text(
                """
                UPDATE tickets
                SET status = 'refunded'
                WHERE order_item_id IN (SELECT id FROM order_items WHERE order_id = :oid)
                """
            ),
            {"oid": p["order_id"]},
        )

    if request:
        await _audit(db, admin_user["id"], "refund.create", "refund", str(row["id"]), request)

    await db.commit()
    return dict(row)


# --------------------
# ANALYTICS
# --------------------
@app.post(
    "/analytics/ingest",
    response_model=Message,
    tags=["analytics"],
    summary="Ingest analytics event",
)
async def ingest_analytics(
    payload: AnalyticsIngest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    authorization: str | None = Header(default=None),
) -> Message:
    """Ingest an analytics event.

    If Authorization is provided and valid, associates with user_id; otherwise uses anonymous_id.
    """
    user_id: str | None = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        try:
            decoded = jwt.decode(
                token,
                get_settings().jwt_secret,
                algorithms=[get_settings().jwt_algorithm],
            )
            if decoded.get("typ") == "access":
                user_id = decoded.get("sub")
        except jwt.PyJWTError:
            user_id = None

    occurred_at = payload.occurred_at or _now()
    await db.execute(
        text(
            """
            INSERT INTO analytics_events (user_id, anonymous_id, event_name, properties, occurred_at)
            VALUES (:uid, :anon, :name, :props::jsonb, :at)
            """
        ),
        {
            "uid": user_id,
            "anon": payload.anonymous_id,
            "name": payload.event_name,
            "props": json.dumps(payload.properties or {}),
            "at": occurred_at,
        },
    )
    await _audit(
        db,
        user_id,
        "analytics.ingest",
        "analytics_event",
        None,
        request,
        details={"event_name": payload.event_name},
    )
    await db.commit()
    return Message(message="ok")


@app.get(
    "/analytics/summary",
    response_model=AnalyticsSummary,
    tags=["analytics"],
    summary="Analytics summary (admin)",
)
async def analytics_summary(
    from_at: datetime,
    to_at: datetime,
    db: AsyncSession = Depends(get_db),
    admin_user: dict[str, Any] = Depends(lambda: require_role("admin")),
) -> AnalyticsSummary:
    """Basic analytics aggregation grouped by event_name (admin only)."""
    res = await db.execute(
        text(
            """
            SELECT event_name, count(*) as cnt
            FROM analytics_events
            WHERE occurred_at >= :from_at AND occurred_at <= :to_at
            GROUP BY event_name
            ORDER BY cnt DESC
            """
        ),
        {"from_at": from_at, "to_at": to_at},
    )
    summary: dict[str, int] = {r[0]: int(r[1]) for r in res.all()}
    return AnalyticsSummary(from_at=from_at, to_at=to_at, by_event_name=summary)
