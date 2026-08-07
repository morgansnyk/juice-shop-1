/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

const insecurity = require('../lib/insecurity')
const db = require('../data/mongodb')

function filterOrders (orders, query, status) {
  let filtered = orders
  const q = (typeof query === 'string' ? query : '').trim()
  if (q.length > 0) {
    const searchTerm = q.toLowerCase().substring(0, 200)
    filtered = filtered.filter((order) => {
      const matchesOrderId = order.orderId && order.orderId.toLowerCase().includes(searchTerm)
      const matchesProduct = order.products && order.products.some((product) =>
        product.name && product.name.toLowerCase().includes(searchTerm)
      )
      return matchesOrderId || matchesProduct
    })
  }
  if (status === 'delivered') {
    filtered = filtered.filter((order) => order.delivered)
  } else if (status === 'in-transit') {
    filtered = filtered.filter((order) => !order.delivered)
  }
  return filtered
}

module.exports.orderHistory = function orderHistory () {
  return async (req, res, next) => {
    const loggedInUser = insecurity.authenticatedUsers.get(req.headers.authorization.replace('Bearer ', ''))
    if (loggedInUser && loggedInUser.data && loggedInUser.data.email && loggedInUser.data.id) {
      const email = loggedInUser.data.email
      const updatedEmail = email.replace(/[aeiou]/gi, '*')
      const orders = await db.orders.find({ email: updatedEmail })
      const query = typeof req.query.q === 'string' ? req.query.q : ''
      const status = typeof req.query.status === 'string' ? req.query.status : ''
      const filtered = filterOrders(orders, query, status)
      res.status(200).json({ status: 'success', data: filtered })
    } else {
      next(new Error('Blocked illegal activity by ' + req.connection.remoteAddress))
    }
  }
}

module.exports.allOrders = function allOrders () {
  return async (req, res, next) => {
    const orders = await db.orders.find()
    res.status(200).json({ status: 'success', data: orders.reverse() })
  }
}

module.exports.toggleDeliveryStatus = function toggleDeliveryStatus () {
  return async (req, res, next) => {
    const orderId = typeof req.params.id === 'string' ? req.params.id : ''
    if (!orderId || !/^[\w-]+$/.test(orderId)) {
      res.status(400).json({ status: 'error', error: 'Invalid order identifier' })
      return
    }
    const deliveryStatus = !req.body.deliveryStatus
    const eta = deliveryStatus ? '0' : '1'
    await db.orders.update({ _id: orderId }, { $set: { delivered: deliveryStatus, eta: eta } })
    res.status(200).json({ status: 'success' })
  }
}
