/*
 * Fully client-side cart. No backend endpoint backs this -- it lives in
 * sessionStorage on the storefront's own origin and never talks to MLPSAPS.
 */

const Cart = {
  KEY: "basecamp_cart",

  read() {
    try {
      return JSON.parse(sessionStorage.getItem(this.KEY)) || {};
    } catch (e) {
      return {};
    }
  },

  write(cart) {
    sessionStorage.setItem(this.KEY, JSON.stringify(cart));
    Cart.updateBadge();
  },

  add(productId, qty = 1) {
    const cart = this.read();
    cart[productId] = (cart[productId] || 0) + qty;
    this.write(cart);
  },

  setQty(productId, qty) {
    const cart = this.read();
    if (qty <= 0) {
      delete cart[productId];
    } else {
      cart[productId] = qty;
    }
    this.write(cart);
  },

  remove(productId) {
    this.setQty(productId, 0);
  },

  clear() {
    sessionStorage.removeItem(this.KEY);
    Cart.updateBadge();
  },

  count() {
    return Object.values(this.read()).reduce((a, b) => a + b, 0);
  },

  updateBadge() {
    const badge = document.getElementById("cart-count");
    if (!badge) return;
    const n = Cart.count();
    badge.textContent = n;
    badge.hidden = n === 0;
  },
};

document.addEventListener("DOMContentLoaded", () => Cart.updateBadge());
