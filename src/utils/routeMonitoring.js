const METERS_PER_RADIAN = 6371000;
const radians = value => value * Math.PI / 180;

function validPoint(point) {
  return point && typeof point.lat === 'number' && Number.isFinite(point.lat)
    && typeof point.lng === 'number' && Number.isFinite(point.lng)
    && Math.abs(point.lat) <= 90 && Math.abs(point.lng) <= 180;
}

function normalizeRoutePoints(points) {
  if (!Array.isArray(points) || points.length < 2 || points.length > 10000
      || !points.every(validPoint)) return null;
  return points.map(({ lat, lng }) => ({ lat, lng }));
}

// Project each short road segment to local meters. Check the segments, rather
// than vertices, so a straight road with sparse geometry is still on route.
function distanceToRouteMeters(point, points) {
  const latitudeScale = radians(1) * METERS_PER_RADIAN;
  const longitudeScale = latitudeScale * Math.cos(radians(point.lat));
  let nearest = Infinity;
  for (let i = 1; i < points.length; i++) {
    const ax = (points[i - 1].lng - point.lng) * longitudeScale;
    const ay = (points[i - 1].lat - point.lat) * latitudeScale;
    const bx = (points[i].lng - point.lng) * longitudeScale;
    const by = (points[i].lat - point.lat) * latitudeScale;
    const dx = bx - ax, dy = by - ay;
    const lengthSquared = dx * dx + dy * dy;
    const fraction = lengthSquared === 0 ? 0
      : Math.max(0, Math.min(1, -(ax * dx + ay * dy) / lengthSquared));
    nearest = Math.min(nearest, Math.hypot(ax + fraction * dx, ay + fraction * dy));
  }
  return nearest;
}

function distanceMeters(a, b) {
  return distanceToRouteMeters(a, [b, b]);
}

function jsonValue(value, fallback) {
  if (typeof value !== 'string') return value || fallback;
  try { return JSON.parse(value); } catch { return fallback; }
}

function currentRouteLeg(trip) {
  if (['accepted', 'pickup'].includes(trip.status)) {
    const target = { lat: Number(trip.pickup_lat), lng: Number(trip.pickup_lng) };
    return { key: 'pickup', target: trip.pickup_lat == null || trip.pickup_lng == null ? null : target };
  }
  if (!['ongoing', 'arrived'].includes(trip.status)) return null;
  const stops = trip.service_type === 'shared' ? jsonValue(trip.shared_dropoffs, []) : [];
  const index = stops.findIndex(stop => stop.status !== 'dropped');
  if (stops.length && index < 0) return null;
  const stop = index < 0 ? null : stops[index];
  const lat = stop?.lat ?? trip.destination_lat;
  const lng = stop?.lng ?? trip.destination_lng;
  return { key: `dropoff:${Math.max(0, index)}`,
    target: lat == null || lng == null ? null : { lat: Number(lat), lng: Number(lng) } };
}

function routeForTrip(trip) {
  const leg = currentRouteLeg(trip);
  const routes = jsonValue(trip.designated_routes, {});
  return { leg, route: leg ? routes[leg.key] || null : null };
}

function routeToleranceMeters() {
  const configured = Number(process.env.TODAGO_ROUTE_TOLERANCE_METERS);
  return Number.isFinite(configured) && configured >= 50 && configured <= 2000
    ? configured : 200;
}

module.exports = { validPoint, normalizeRoutePoints, distanceToRouteMeters,
  distanceMeters, currentRouteLeg, routeForTrip, routeToleranceMeters };
