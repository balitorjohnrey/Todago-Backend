const { features } = require('../data/panabo-carmen-boundaries.json');
const { validPoint } = require('./routeMonitoring');

function compilePolygon(rings) {
  let minLat = Infinity, maxLat = -Infinity, minLng = Infinity, maxLng = -Infinity;
  for (const [lng, lat] of rings[0]) {
    minLat = Math.min(minLat, lat);
    maxLat = Math.max(maxLat, lat);
    minLng = Math.min(minLng, lng);
    maxLng = Math.max(maxLng, lng);
  }
  return { minLat, maxLat, minLng, maxLng, rings };
}

const defaults = features.map(({ properties, geometry }) => ({
  name: properties.name,
  polygons: (geometry.type === 'Polygon' ? [geometry.coordinates] : geometry.coordinates)
    .map(compilePolygon),
}));

let lastConfig;
let configuredAreas = defaults;
function serviceAreas() {
  const config = process.env.TODAGO_SERVICE_AREAS_JSON;
  if (config === lastConfig) return configuredAreas;
  lastConfig = config;
  configuredAreas = defaults;
  if (!config) return configuredAreas;
  try {
    const overrides = JSON.parse(config);
    if (!Array.isArray(overrides)) return configuredAreas;
    const valid = overrides.filter(Boolean).map(area => {
      const { minLat, maxLat, minLng, maxLng } = Object.fromEntries(
        ['minLat', 'maxLat', 'minLng', 'maxLng'].map(key => [key, Number.parseFloat(area[key])]));
      if (!validPoint({ lat: minLat, lng: minLng }) || !validPoint({ lat: maxLat, lng: maxLng })
          || minLat >= maxLat || minLng >= maxLng) return null;
      return { name: String(area.name || 'Service area'), polygons: [{ minLat, maxLat, minLng, maxLng }] };
    }).filter(Boolean);
    if (valid.length) configuredAreas = valid;
  } catch {
    // An absent or unusable override falls back to the bundled boundaries.
  }
  return configuredAreas;
}

// Returns -1 outside, 0 on an edge, and 1 inside. GeoJSON stores longitude first.
function ringPosition(lat, lng, ring) {
  let inside = false;
  for (let i = 1; i < ring.length; i++) {
    const [aLng, aLat] = ring[i - 1];
    const [bLng, bLat] = ring[i];
    const cross = (lng - aLng) * (bLat - aLat) - (lat - aLat) * (bLng - aLng);
    if (Math.abs(cross) < 1e-12
        && lng >= Math.min(aLng, bLng) && lng <= Math.max(aLng, bLng)
        && lat >= Math.min(aLat, bLat) && lat <= Math.max(aLat, bLat)) return 0;
    if ((aLat > lat) !== (bLat > lat)
        && lng < (bLng - aLng) * (lat - aLat) / (bLat - aLat) + aLng) inside = !inside;
  }
  return inside ? 1 : -1;
}

function contains(lat, lng, polygon) {
  if (lat < polygon.minLat || lat > polygon.maxLat || lng < polygon.minLng || lng > polygon.maxLng) return false;
  if (!polygon.rings) return true; // Explicit rectangle override.
  const [outer, ...holes] = polygon.rings;
  return ringPosition(lat, lng, outer) >= 0 && holes.every(ring => ringPosition(lat, lng, ring) <= 0);
}

function classifyServiceArea(lat, lng) {
  const areas = serviceAreas();
  const valid = validPoint({ lat, lng });
  const matched = valid && areas.find(area => area.polygons.some(polygon => contains(lat, lng, polygon)));
  return {
    within_service_area: valid ? Boolean(matched) : null,
    service_area_name: matched ? matched.name : null,
    allowed_service_areas: [...new Set(areas.map(area => area.name))],
  };
}

module.exports = { classifyServiceArea };
