import { useEffect } from 'react'
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet'
import L from 'leaflet'
import 'leaflet/dist/leaflet.css'

// Custom neon marker (avoids the default broken-icon issue with bundlers).
const neonIcon = L.divIcon({
  className: 'neon-marker',
  html: '<div class="neon-pin"></div>',
  iconSize: [14, 14],
  iconAnchor: [7, 7],
  popupAnchor: [0, -8],
})

function FitBounds({ points }) {
  const map = useMap()
  useEffect(() => {
    if (!points.length) return
    if (points.length === 1) {
      map.setView([points[0].lat, points[0].lon], 6)
    } else {
      map.fitBounds(points.map((p) => [p.lat, p.lon]), { padding: [40, 40] })
    }
  }, [points, map])
  return null
}

export default function ResultMap({ points }) {
  if (!points.length) {
    return (
      <div className="map-empty">
        <div>
          <div className="mono-label">// no geolocation</div>
          <p className="muted" style={{ marginTop: 8, maxWidth: 280 }}>
            No coordinates in this result. Run an IP target (or a domain that
            resolves) to light up the map.
          </p>
        </div>
      </div>
    )
  }

  const center = [points[0].lat, points[0].lon]

  return (
    <div className="map-wrap">
      <MapContainer
        center={center}
        zoom={4}
        scrollWheelZoom={false}
        style={{ height: '100%', width: '100%' }}
      >
        <TileLayer
          attribution='&copy; OpenStreetMap &copy; CARTO'
          url="https://{s}.basemap.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
        />
        {points.map((p, i) => (
          <Marker key={i} position={[p.lat, p.lon]} icon={neonIcon}>
            <Popup>
              <strong>{p.target}</strong>
              <br />
              {p.label}
              {p.isp ? (
                <>
                  <br />
                  <span style={{ opacity: 0.7 }}>{p.isp}</span>
                </>
              ) : null}
            </Popup>
          </Marker>
        ))}
        <FitBounds points={points} />
      </MapContainer>
    </div>
  )
}
