/**
 * WaveDivider — SVG wave section dividers
 * Coastal Breeze signature element
 */

interface WaveDividerProps {
  position: "top" | "bottom";
  color?: string;
  className?: string;
}

export default function WaveDivider({ position, color = "#f8fafc", className = "" }: WaveDividerProps) {
  if (position === "top") {
    return (
      <div className={`w-full overflow-hidden leading-[0] ${className}`}>
        <svg
          viewBox="0 0 1440 80"
          preserveAspectRatio="none"
          className="w-full h-[40px] sm:h-[60px] md:h-[80px] block"
          style={{ transform: "scaleY(-1)" }}
        >
          <path
            d="M0,80 L0,40 C120,65 240,75 360,60 C480,45 600,15 720,10 C840,5 960,25 1080,40 C1200,55 1320,65 1380,68 L1440,70 L1440,80 Z"
            fill={color}
          />
        </svg>
      </div>
    );
  }

  return (
    <div className={`w-full overflow-hidden leading-[0] ${className}`}>
      <svg
        viewBox="0 0 1440 80"
        preserveAspectRatio="none"
        className="w-full h-[40px] sm:h-[60px] md:h-[80px] block"
      >
        <path
          d="M0,0 L0,40 C120,15 240,5 360,20 C480,35 600,65 720,70 C840,75 960,55 1080,40 C1200,25 1320,15 1380,12 L1440,10 L1440,0 Z"
          fill={color}
        />
      </svg>
    </div>
  );
}
