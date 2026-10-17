import { AdaptiveDpr } from '@react-three/drei';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import * as THREE from 'three';
import { statusToPlate } from '../status/statusToPlate';
import { buildPlates } from './layout';
import { plateLook, readTokens } from './tones';

const DOME = 0.045; // depth curvature of the shield
const PARALLAX = THREE.MathUtils.degToRad(6); // cursor parallax cap (brief: 6 degrees)
const BREACH_TILT = THREE.MathUtils.degToRad(12);

const tmp = new THREE.Object3D();
const tmpColor = new THREE.Color();

function plateTransform(p, look, lift) {
  const z = -DOME * (p.x * p.x + p.y * p.y);
  tmp.position.set(p.x, p.y, z + lift + (look.kind === 'breached' ? 0.35 : 0));
  // Each plate faces outward from the dome; breached plates tilt out a further 12 degrees.
  tmp.rotation.set(Math.PI / 2 + p.y * DOME * 2, 0, 0);
  tmp.rotateZ(p.x * DOME * 2);
  if (look.kind === 'breached') tmp.rotateX(-BREACH_TILT);
  tmp.scale.setScalar(1);
  tmp.updateMatrix();
  return tmp.matrix;
}

function Plates({ plates, tokens, mode, reducedMotion, onHover, onSelect, focusedId }) {
  const mesh = useRef();
  const group = useRef();
  const hovered = useRef(-1);
  const { invalidate } = useThree();
  const looks = useMemo(() => plates.map((p) => plateLook(p, tokens)), [plates, tokens]);
  const scanning = looks.some((l) => l.kind === 'scanning');
  const animate = !reducedMotion && (mode === 'hero' || scanning);

  const geometry = useMemo(() => {
    const g = new THREE.CylinderGeometry(0.93, 0.93, 0.16, 6, 1);
    g.rotateY(Math.PI / 6); // flat-top hex, matching the 2D grid layout
    return g;
  }, []);

  const paint = (time = 0) => {
    const m = mesh.current;
    if (!m) return;
    plates.forEach((p, i) => {
      const look = looks[i];
      const isFocus = p.dataset && (i === hovered.current || p.dataset.dataset_id === focusedId);
      m.setMatrixAt(i, plateTransform(p, look, isFocus ? 0.15 : 0));
      tmpColor.set(look.color);
      // Filler stays a dull empty plate; "not scanned" is a mid-grey plate, clearly not filler.
      if (look.kind === 'filler') tmpColor.multiplyScalar(1.35);
      if (look.kind === 'unscanned') tmpColor.multiplyScalar(0.5);
      if (look.kind === 'degraded') tmpColor.multiplyScalar(0.8);
      if (look.kind === 'scanning' && !reducedMotion) {
        tmpColor.lerp(new THREE.Color('#ffffff'), 0.25 + 0.25 * Math.sin(time * 3));
      }
      // Hero only: plates light up in sequence as if being scanned, one at a time.
      if (mode === 'hero' && !reducedMotion && p.dataset) {
        const turn = Math.floor(time / 0.7) % plates.length;
        if (turn === i) tmpColor.lerp(new THREE.Color(tokens.accent), 0.6);
      }
      if (isFocus) tmpColor.lerp(new THREE.Color('#ffffff'), 0.15);
      m.setColorAt(i, tmpColor);
    });
    m.instanceMatrix.needsUpdate = true;
    if (m.instanceColor) m.instanceColor.needsUpdate = true;
  };

  useLayoutEffect(() => { paint(0); invalidate(); });

  useFrame((state) => {
    if (!animate && hovered.current < 0) return;
    const t = state.clock.getElapsedTime();
    if (group.current && !reducedMotion) {
      const idle = mode === 'hero' ? Math.sin(t * 0.25) * 0.08 : 0;
      group.current.rotation.y = THREE.MathUtils.lerp(group.current.rotation.y, state.pointer.x * PARALLAX + idle, 0.05);
      group.current.rotation.x = THREE.MathUtils.lerp(group.current.rotation.x, -state.pointer.y * PARALLAX, 0.05);
    }
    paint(t);
  });

  return (
    <group ref={group}>
      <instancedMesh
        ref={mesh}
        args={[geometry, undefined, plates.length]}
        onPointerMove={(e) => {
          e.stopPropagation();
          const i = e.instanceId;
          if (!plates[i]?.dataset) { hovered.current = -1; onHover(null); return; }
          hovered.current = i;
          onHover({ dataset: plates[i].dataset, x: e.nativeEvent.offsetX, y: e.nativeEvent.offsetY });
          invalidate();
        }}
        onPointerOut={() => { hovered.current = -1; onHover(null); invalidate(); }}
        onClick={(e) => {
          const d = plates[e.instanceId]?.dataset;
          if (d && onSelect) onSelect(d);
        }}
      >
        <meshStandardMaterial metalness={0.55} roughness={0.38} />
      </instancedMesh>
    </group>
  );
}

/**
 * The Bastion shield in WebGL: one instanced hex plate per dataset on a shallow dome,
 * lit by one lamp from the top-left (matching the CSS shadows).
 * mode "hero": idle sway + sequential scan highlight; mode "compact": still unless a
 * dataset is scanning (frameloop "demand" otherwise).
 */
export default function Shield3D({ datasets, mode = 'compact', theme, reducedMotion, onSelect, focusedId, onReady }) {
  const plates = useMemo(() => buildPlates(datasets), [datasets]);
  const [tokens, setTokens] = useState(() => readTokens());
  const [hover, setHover] = useState(null);
  useEffect(() => { setTokens(readTokens()); }, [theme]);

  const radius = Math.max(...plates.map((p) => Math.hypot(p.x, p.y))) + 1.2;
  const scanning = datasets.some((d) => statusToPlate(d.shown).plate === 'scanning');
  const live = !reducedMotion && (mode === 'hero' || scanning);

  return (
    <div className="shield-3d" onPointerLeave={() => setHover(null)}>
      <Canvas
        dpr={[1, 2]}
        frameloop={live ? 'always' : 'demand'}
        camera={{ position: [0, 0, radius * 2.6], fov: 40 }}
        gl={{ antialias: true, alpha: true, powerPreference: 'low-power' }}
        onCreated={() => onReady?.()}
        aria-hidden="true"
      >
        <AdaptiveDpr pixelated={false} />
        <ambientLight intensity={0.9} />
        <directionalLight position={[-6, 6, 8]} intensity={1.6} />
        <Plates
          plates={plates}
          tokens={tokens}
          mode={mode}
          reducedMotion={reducedMotion}
          onHover={setHover}
          onSelect={onSelect}
          focusedId={focusedId}
        />
      </Canvas>
      {hover && (
        <div className="shield-tip" style={{ left: hover.x, top: hover.y }} role="presentation">
          <strong>{hover.dataset.original_filename}</strong>
          <span>{statusToPlate(hover.dataset.shown).label}</span>
          <span className="mono">{hover.dataset.scanned_at ? new Date(hover.dataset.scanned_at).toLocaleString() : 'not scanned'}</span>
        </div>
      )}
    </div>
  );
}
