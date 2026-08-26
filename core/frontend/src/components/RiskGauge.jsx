import { postureFromScore } from '../utils/severity.js'

// RiskGauge renders the "Master Threat Posture" circular gauge: an SVG
// arc (270-degree sweep, gauge-style) whose fill color and end-cap label
// derive from the composite 0-100 risk score, matching the four severity
// bands used everywhere else in the app.
export default function RiskGauge({ score = 0, size = 168 }) {
  const posture = postureFromScore(score)
  const stroke = 14
  const radius = (size - stroke) / 2
  const circumference = 2 * Math.PI * radius
  // 270-degree gauge: draw 75% of a full circle, leave a 90-degree gap at
  // the bottom for a classic speedometer look.
  const arcFraction = 0.75
  const arcLength = circumference * arcFraction
  const fillLength = arcLength * (score / 100)
  const center = size / 2

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-[225deg]">
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke="#e2e8f0"
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${arcLength} ${circumference}`}
          />
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke={posture.color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${fillLength} ${circumference}`}
            style={{ transition: 'stroke-dasharray 0.6s ease, stroke 0.4s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-extrabold text-slate-900 tabular-nums">{score}</span>
          <span className="text-[10px] font-semibold text-slate-400 -mt-0.5">/ 100</span>
        </div>
      </div>
      <span
        className="mt-1 inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-bold tracking-wide ring-1 ring-inset"
        style={{ color: posture.color, backgroundColor: `${posture.color}14`, borderColor: posture.color }}
      >
        {posture.label}
      </span>
      <p className="text-xs text-slate-400 mt-1 text-center max-w-[160px]">{posture.text}</p>
    </div>
  )
}
