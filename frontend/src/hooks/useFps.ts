import { useEffect, useState } from 'react'

/** Frames per second measured with requestAnimationFrame, sampled every `windowMs`. */
export function useFps(windowMs = 500): number {
  const [fps, setFps] = useState(0)

  useEffect(() => {
    let frames = 0
    let windowStart = performance.now()
    let handle = 0

    const tick = (now: number) => {
      frames++
      const elapsed = now - windowStart
      if (elapsed >= windowMs) {
        setFps(Math.round((frames * 1000) / elapsed))
        frames = 0
        windowStart = now
      }
      handle = requestAnimationFrame(tick)
    }
    handle = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(handle)
  }, [windowMs])

  return fps
}
