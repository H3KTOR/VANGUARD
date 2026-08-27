// RiskGauge.test.jsx
//
// Covers the "Master Threat Posture" gauge's pure derivation logic
// (score -> posture label/color/text via utils/severity.postureFromScore)
// and the SVG rendering contract the rest of the dashboard depends on:
// two concentric <circle> arcs (track + fill), the numeric score label,
// and the /100 suffix. These are unit-level checks, not pixel/visual
// regression tests -- they guard against the score->band boundaries and
// the arc-length math silently breaking.

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import RiskGauge from '../RiskGauge.jsx'
import { postureFromScore, SEVERITY_COLORS } from '../../utils/severity.js'

describe('postureFromScore (pure logic backing the gauge)', () => {
  it('classifies 0 as SECURE', () => {
    expect(postureFromScore(0).label).toBe('SECURE')
    expect(postureFromScore(0).color).toBe(SEVERITY_COLORS.LOW)
  })

  it('classifies the low/guarded boundary correctly (29 vs 30)', () => {
    expect(postureFromScore(29).label).toBe('SECURE')
    expect(postureFromScore(30).label).toBe('GUARDED')
  })

  it('classifies the guarded/elevated boundary correctly (59 vs 60)', () => {
    expect(postureFromScore(59).label).toBe('GUARDED')
    expect(postureFromScore(60).label).toBe('ELEVATED')
  })

  it('classifies the elevated/critical boundary correctly (79 vs 80)', () => {
    expect(postureFromScore(79).label).toBe('ELEVATED')
    expect(postureFromScore(80).label).toBe('CRITICAL')
  })

  it('classifies 100 as CRITICAL with the critical color', () => {
    const posture = postureFromScore(100)
    expect(posture.label).toBe('CRITICAL')
    expect(posture.color).toBe(SEVERITY_COLORS.CRITICAL)
  })
})

describe('<RiskGauge />', () => {
  it('renders the numeric score and the /100 suffix', () => {
    render(<RiskGauge score={42} />)
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('/ 100')).toBeInTheDocument()
  })

  it('renders the posture badge label matching the score band', () => {
    render(<RiskGauge score={85} />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    expect(screen.getByText('Active exploitation likely')).toBeInTheDocument()
  })

  it('renders exactly two SVG circle arcs (track + fill)', () => {
    const { container } = render(<RiskGauge score={50} />)
    const circles = container.querySelectorAll('svg circle')
    expect(circles).toHaveLength(2)
  })

  it('scales the fill arc dasharray proportionally to the score', () => {
    const { container: lowContainer } = render(<RiskGauge score={10} />)
    const { container: highContainer } = render(<RiskGauge score={90} />)

    const lowFillCircle = lowContainer.querySelectorAll('svg circle')[1]
    const highFillCircle = highContainer.querySelectorAll('svg circle')[1]

    const lowDash = parseFloat(lowFillCircle.getAttribute('stroke-dasharray').split(' ')[0])
    const highDash = parseFloat(highFillCircle.getAttribute('stroke-dasharray').split(' ')[0])

    expect(highDash).toBeGreaterThan(lowDash)
  })

  it('applies the posture color to the fill arc stroke', () => {
    const { container } = render(<RiskGauge score={90} />)
    const fillCircle = container.querySelectorAll('svg circle')[1]
    expect(fillCircle).toHaveAttribute('stroke', SEVERITY_COLORS.CRITICAL)
  })

  it('respects a custom size prop for the svg viewport', () => {
    const { container } = render(<RiskGauge score={0} size={240} />)
    const svg = container.querySelector('svg')
    expect(svg).toHaveAttribute('width', '240')
    expect(svg).toHaveAttribute('height', '240')
  })

  it('defaults to score=0 / SECURE when no props are passed', () => {
    render(<RiskGauge />)
    expect(screen.getByText('0')).toBeInTheDocument()
    expect(screen.getByText('SECURE')).toBeInTheDocument()
  })
})
