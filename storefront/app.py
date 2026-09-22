"""
Basecamp Supply Co. -- demo storefront.

A separate Flask app (port 5001) from MLPSAPS (port 5000). It has NO auth
logic of its own: Register/Login/Account/Checkout all call MLPSAPS's real
/api/auth/* endpoints directly from the browser via fetch(). This file just
serves the pages; the auth flow lives in static/js/auth.js.
"""

import os
from flask import Flask, render_template

# The storefront only needs to know where MLPSAPS lives so it can hand that
# URL to the browser-side JS. It never talks to MLPSAPS itself server-side.
MLPSAPS_API_BASE = os.environ.get("MLPSAPS_API_BASE", "http://127.0.0.1:5000")

app = Flask(__name__)

PRODUCTS = [
    {
        "id": 1,
        "name": "Alpine 40L Pack",
        "price": 189.00,
        "blurb": "Top-loading pack with a rain-ready roll closure.",
        "tag": "Backpacks",
    },
    {
        "id": 2,
        "name": "Basin 2P Tent",
        "price": 249.00,
        "blurb": "Freestanding two-person tent, 3.1kg packed.",
        "tag": "Shelter",
    },
    {
        "id": 3,
        "name": "Ridgeline Sleeping Bag",
        "price": 159.00,
        "blurb": "Down-fill, rated to -6\u00b0C.",
        "tag": "Sleep",
    },
    {
        "id": 4,
        "name": "Ember Camp Stove",
        "price": 65.00,
        "blurb": "Folding titanium stove, boils 1L in under 4 minutes.",
        "tag": "Cook",
    },
    {
        "id": 5,
        "name": "Traverse Trekking Poles",
        "price": 79.00,
        "blurb": "Carbon-fibre, collapsible to 38cm.",
        "tag": "Trail",
    },
    {
        "id": 6,
        "name": "Waypoint Headlamp",
        "price": 39.00,
        "blurb": "350 lumens, rechargeable, dims automatically at dusk settings.",
        "tag": "Gear",
    },
]


def render(page, **ctx):
    return render_template(page, api_base=MLPSAPS_API_BASE, products=PRODUCTS, **ctx)


@app.route("/")
def home():
    return render("index.html")


@app.route("/cart")
def cart():
    return render("cart.html")


@app.route("/register")
def register():
    return render("register.html")


@app.route("/login")
def login():
    return render("login.html")


@app.route("/account")
def account():
    # Auth is enforced client-side (auth-guard.js): if there's no valid
    # MLPSAPS token, the page JS redirects to /login before showing anything.
    return render("account.html")


@app.route("/checkout")
def checkout():
    return render("checkout.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
