/**
 * Hono middleware for Service Auth Token (SAT) verification
 *
 * Provides easy integration of SAT authentication into Hono-based services
 */

import type { Context, Next } from 'hono'
import { decodeToken, verifyToken, type ServiceKeyRegistry } from './service-auth'

export interface ServiceAuthContext {
  serviceId: string
  nodeId: string
  payload?: Record<string, any>
}

/**
 * Hono middleware for SAT verification
 *
 * Adds `c.get('auth')` with service authentication context
 *
 * @param registry - Service key registry for verification
 * @param options - Optional configuration
 */
export function serviceAuth(
  registry: ServiceKeyRegistry,
  options?: {
    /** Allow requests without auth (useful for health checks) */
    optional?: boolean
    /** Allowed service IDs (if specified, only these services can access) */
    allowedServices?: string[]
  }
) {
  return async (c: Context, next: Next) => {
    const authHeader = c.req.header('Authorization')

    // If no auth header and optional, allow through
    if (!authHeader && options?.optional) {
      return next()
    }

    if (!authHeader) {
      return c.json({ error: 'Missing Authorization header' }, 401)
    }

    // Decode token
    const token = decodeToken(authHeader)
    if (!token) {
      return c.json({ error: 'Invalid token format' }, 401)
    }

    // Check if service is allowed
    if (options?.allowedServices && !options.allowedServices.includes(token.serviceId)) {
      return c.json({
        error: 'Service not authorized',
        allowedServices: options.allowedServices
      }, 403)
    }

    // Get public key from registry
    const publicKey = registry.get(token.serviceId, token.nodeId)
    if (!publicKey) {
      return c.json({
        error: 'Service not registered',
        serviceId: token.serviceId,
        nodeId: token.nodeId
      }, 403)
    }

    // Verify token
    const valid = await verifyToken(token, publicKey)
    if (!valid) {
      return c.json({ error: 'Invalid token signature or expired' }, 401)
    }

    // Add auth context to request
    c.set('auth', {
      serviceId: token.serviceId,
      nodeId: token.nodeId,
      payload: token.payload
    } as ServiceAuthContext)

    return next()
  }
}

/**
 * Helper to get auth context from Hono context
 *
 * @param c - Hono context
 * @returns Service auth context, or null if not authenticated
 */
export function getAuthContext(c: Context): ServiceAuthContext | null {
  return c.get('auth') || null
}

/**
 * Require specific service(s) to access an endpoint
 *
 * Usage:
 * ```ts
 * app.delete('/content/:hash',
 *   serviceAuth(registry),
 *   requireService('ledger'),
 *   async (c) => {
 *     // Only ledger service can access
 *   }
 * )
 * ```
 */
export function requireService(...serviceIds: string[]) {
  return async (c: Context, next: Next) => {
    const auth = getAuthContext(c)

    if (!auth) {
      return c.json({ error: 'Authentication required' }, 401)
    }

    if (!serviceIds.includes(auth.serviceId)) {
      return c.json({
        error: 'Service not authorized for this endpoint',
        required: serviceIds,
        actual: auth.serviceId
      }, 403)
    }

    return next()
  }
}

/**
 * Require specific node ID to access an endpoint
 *
 * Useful for endpoints that should only be accessed by the local node
 */
export function requireNode(nodeId: string) {
  return async (c: Context, next: Next) => {
    const auth = getAuthContext(c)

    if (!auth) {
      return c.json({ error: 'Authentication required' }, 401)
    }

    if (auth.nodeId !== nodeId) {
      return c.json({
        error: 'Node not authorized',
        required: nodeId,
        actual: auth.nodeId
      }, 403)
    }

    return next()
  }
}
