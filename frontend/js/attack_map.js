/**
 * CyberGuard AI - Canvas World Attack Map Engine
 * Renders real-time global telemetry, animated missile/arc trajectories, and impact ripples.
 */

class CyberAttackMap {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    
    // Core SOC Data Center Target (San Francisco coordinates)
    this.target = { name: "CyberGuard Core SOC", lat: 37.7749, lng: -122.4194 };
    
    this.activeArcs = [];
    this.impactParticles = [];
    this.originBeacons = [];
    
    this.resize();
    window.addEventListener('resize', () => this.resize());
    
    // Start animation loop
    this.lastTime = performance.now();
    this.animate = this.animate.bind(this);
    requestAnimationFrame(this.animate);
  }

  resize() {
    if (!this.canvas) return;
    const rect = this.canvas.parentElement.getBoundingClientRect();
    this.width = this.canvas.width = rect.width;
    this.height = this.canvas.height = rect.height;
  }

  // Convert GPS Lat/Lng to Canvas XY using Equirectangular projection
  latLngToXY(lat, lng) {
    const x = ((lng + 180) / 360) * this.width;
    const y = ((90 - lat) / 180) * this.height;
    return { x, y };
  }

  // Triggered when an attack or event is detected
  addAttack(srcLat, srcLng, srcCountry, threatType, severity) {
    const origin = this.latLngToXY(srcLat, srcLng);
    const dest = this.latLngToXY(this.target.lat, this.target.lng);
    
    let color = "#38bdf8"; // default blue
    if (severity === "Critical") color = "#ff0055"; // neon red
    else if (severity === "High") color = "#f59e0b"; // amber
    else if (severity === "Medium") color = "#8b5cf6"; // purple

    // Arc trajectory with height offset
    const arc = {
      src: origin,
      dst: dest,
      progress: 0,
      speed: 0.015 + Math.random() * 0.01,
      color: color,
      country: srcCountry,
      threatType: threatType,
      severity: severity,
      tail: []
    };
    this.activeArcs.push(arc);

    // Add pulsing beacon at origin
    this.originBeacons.push({
      x: origin.x,
      y: origin.y,
      radius: 4,
      maxRadius: 24,
      alpha: 1.0,
      color: color,
      label: srcCountry
    });
  }

  createImpactRipples(x, y, color) {
    for (let i = 0; i < 14; i++) {
      const angle = Math.random() * Math.PI * 2;
      const speed = 1.0 + Math.random() * 3.5;
      this.impactParticles.push({
        x: x,
        y: y,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        radius: 1.5 + Math.random() * 2,
        alpha: 1.0,
        decay: 0.02 + Math.random() * 0.02,
        color: color
      });
    }
  }

  drawMapGrid() {
    const ctx = this.ctx;
    ctx.strokeStyle = "rgba(56, 189, 248, 0.05)";
    ctx.lineWidth = 1;

    // Longitudinal grid lines
    for (let x = 0; x < this.width; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, this.height);
      ctx.stroke();
    }
    // Latitudinal lines
    for (let y = 0; y < this.height; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(this.width, y);
      ctx.stroke();
    }

    // World Landmass Dot Grid Matrix (Stylized Cyber Continents)
    ctx.fillStyle = "rgba(56, 189, 248, 0.18)";
    const dotSpacing = 16;
    for (let x = 20; x < this.width; x += dotSpacing) {
      for (let y = 20; y < this.height; y += dotSpacing) {
        // Approximate continent silhouettes mathematically
        const normX = x / this.width;
        const normY = y / this.height;
        
        // Landmass heuristic bounding boxes
        const isNorthAmerica = normX > 0.12 && normX < 0.32 && normY > 0.20 && normY < 0.50;
        const isSouthAmerica = normX > 0.22 && normX < 0.35 && normY > 0.52 && normY < 0.85;
        const isEurope = normX > 0.45 && normX < 0.60 && normY > 0.20 && normY < 0.42;
        const isAfrica = normX > 0.46 && normX < 0.62 && normY > 0.44 && normY < 0.78;
        const isAsia = normX > 0.58 && normX < 0.88 && normY > 0.18 && normY < 0.58;
        const isAustralia = normX > 0.78 && normX < 0.92 && normY > 0.65 && normY < 0.85;

        if (isNorthAmerica || isSouthAmerica || isEurope || isAfrica || isAsia || isAustralia) {
          ctx.beginPath();
          ctx.arc(x, y, 1.2, 0, Math.PI * 2);
          ctx.fill();
        }
      }
    }
  }

  drawTargetBase() {
    const targetXY = this.latLngToXY(this.target.lat, this.target.lng);
    const ctx = this.ctx;

    // Glowing core rings
    const time = performance.now() / 1000;
    const pulse = Math.sin(time * 3) * 3;

    ctx.save();
    ctx.beginPath();
    ctx.arc(targetXY.x, targetXY.y, 8 + pulse, 0, Math.PI * 2);
    ctx.fillStyle = "rgba(0, 242, 254, 0.25)";
    ctx.fill();

    ctx.beginPath();
    ctx.arc(targetXY.x, targetXY.y, 4, 0, Math.PI * 2);
    ctx.fillStyle = "#00f2fe";
    ctx.shadowColor = "#00f2fe";
    ctx.shadowBlur = 15;
    ctx.fill();

    // Shield label
    ctx.fillStyle = "#ffffff";
    ctx.font = "10px JetBrains Mono, monospace";
    ctx.fillText("🛡️ SOC CORE", targetXY.x + 12, targetXY.y + 3);
    ctx.restore();
  }

  animate() {
    if (!this.ctx) return;
    this.ctx.clearRect(0, 0, this.width, this.height);

    // 1. Draw Background Matrix
    this.drawMapGrid();
    this.drawTargetBase();

    // 2. Draw & Update Origin Beacons
    for (let i = this.originBeacons.length - 1; i >= 0; i--) {
      const b = this.originBeacons[i];
      b.radius += 0.35;
      b.alpha -= 0.015;

      this.ctx.save();
      this.ctx.strokeStyle = b.color;
      this.ctx.globalAlpha = Math.max(0, b.alpha);
      this.ctx.lineWidth = 1.5;
      this.ctx.beginPath();
      this.ctx.arc(b.x, b.y, b.radius, 0, Math.PI * 2);
      this.ctx.stroke();

      this.ctx.fillStyle = b.color;
      this.ctx.beginPath();
      this.ctx.arc(b.x, b.y, 3, 0, Math.PI * 2);
      this.ctx.fill();
      this.ctx.restore();

      if (b.alpha <= 0) {
        this.originBeacons.splice(i, 1);
      }
    }

    // 3. Draw & Update Arcs
    for (let i = this.activeArcs.length - 1; i >= 0; i--) {
      const arc = this.activeArcs[i];
      arc.progress += arc.speed;

      // Quadratic Bezier arc with height apex
      const t = arc.progress;
      const p0 = arc.src;
      const p2 = arc.dst;
      const midX = (p0.x + p2.x) / 2;
      const midY = Math.min(p0.y, p2.y) - 70; // Arch upward

      // Current projectile position
      const curX = (1 - t) * (1 - t) * p0.x + 2 * (1 - t) * t * midX + t * t * p2.x;
      const curY = (1 - t) * (1 - t) * p0.y + 2 * (1 - t) * t * midY + t * t * p2.y;

      arc.tail.push({ x: curX, y: curY });
      if (arc.tail.length > 15) arc.tail.shift();

      // Draw faint trajectory guide
      this.ctx.save();
      this.ctx.strokeStyle = "rgba(255, 255, 255, 0.08)";
      this.ctx.lineWidth = 1;
      this.ctx.beginPath();
      this.ctx.moveTo(p0.x, p0.y);
      this.ctx.quadraticCurveTo(midX, midY, p2.x, p2.y);
      this.ctx.stroke();

      // Draw glowing projectile tail
      if (arc.tail.length > 1) {
        for (let k = 0; k < arc.tail.length - 1; k++) {
          this.ctx.beginPath();
          this.ctx.moveTo(arc.tail[k].x, arc.tail[k].y);
          this.ctx.lineTo(arc.tail[k + 1].x, arc.tail[k + 1].y);
          this.ctx.strokeStyle = arc.color;
          this.ctx.lineWidth = (k / arc.tail.length) * 3;
          this.ctx.globalAlpha = k / arc.tail.length;
          this.ctx.shadowColor = arc.color;
          this.ctx.shadowBlur = 8;
          this.ctx.stroke();
        }
      }

      // Draw projectile head
      this.ctx.beginPath();
      this.ctx.arc(curX, curY, 3.5, 0, Math.PI * 2);
      this.ctx.fillStyle = "#ffffff";
      this.ctx.shadowColor = arc.color;
      this.ctx.shadowBlur = 12;
      this.ctx.fill();
      this.ctx.restore();

      // Impact on reaching target
      if (arc.progress >= 1.0) {
        this.createImpactRipples(p2.x, p2.y, arc.color);
        this.activeArcs.splice(i, 1);
      }
    }

    // 4. Draw & Update Impact Particles
    for (let i = this.impactParticles.length - 1; i >= 0; i--) {
      const p = this.impactParticles[i];
      p.x += p.vx;
      p.y += p.vy;
      p.alpha -= p.decay;

      this.ctx.save();
      this.ctx.fillStyle = p.color;
      this.ctx.globalAlpha = Math.max(0, p.alpha);
      this.ctx.shadowColor = p.color;
      this.ctx.shadowBlur = 6;
      this.ctx.beginPath();
      this.ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      this.ctx.fill();
      this.ctx.restore();

      if (p.alpha <= 0) {
        this.impactParticles.splice(i, 1);
      }
    }

    requestAnimationFrame(this.animate);
  }
}

// Global instance variable
window.AttackMap = null;
