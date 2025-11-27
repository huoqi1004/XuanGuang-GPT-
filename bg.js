// 28星宿动态星空背景系统 - 玄光安全GPT
const canvas = document.getElementById('bg-canvas');
const ctx = canvas.getContext('2d');
let w = 0, h = 0, dpr = 1;

// 当前活动页面
let currentPage = 'login';

// 星空元素
let stars = [];
let constellations = [];
let shootingStars = [];
let fogEffects = [];

// 对象池管理 - 优化内存使用
class ObjectPool {
  constructor(createFn, maxSize = 1000) {
    this.pool = [];
    this.createFn = createFn;
    this.maxSize = maxSize;
  }
  
  get() {
    if (this.pool.length > 0) {
      return this.pool.pop();
    }
    return this.createFn();
  }
  
  recycle(obj) {
    if (this.pool.length < this.maxSize) {
      this.pool.push(obj);
    }
  }
}

// 防抖函数 - 优化窗口调整事件
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// 节流函数 - 优化性能密集型操作
function throttle(func, limit) {
  let inThrottle;
  return function() {
    const args = arguments;
    const context = this;
    if (!inThrottle) {
      func.apply(context, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

// 28星宿数据 - 四象七宿
const xiuData = {
  // 东方苍龙七宿
  canglong: [
    { name: '角宿', stars: 2, position: { x: 0.8, y: 0.3 }, color: '#FF5E5B', shape: 'triangle' },
    { name: '亢宿', stars: 4, position: { x: 0.75, y: 0.35 }, color: '#FFBD00', shape: 'line' },
    { name: '氐宿', stars: 4, position: { x: 0.7, y: 0.4 }, color: '#EDFF00', shape: 'line' },
    { name: '房宿', stars: 4, position: { x: 0.65, y: 0.45 }, color: '#7CFF00', shape: 'line' },
    { name: '心宿', stars: 3, position: { x: 0.6, y: 0.5 }, color: '#00FFC4', shape: 'triangle' },
    { name: '尾宿', stars: 9, position: { x: 0.55, y: 0.55 }, color: '#00B8FF', shape: 'fan' },
    { name: '箕宿', stars: 4, position: { x: 0.5, y: 0.6 }, color: '#7C00FF', shape: 'triangle' }
  ],
  // 北方玄武七宿
  xuanwu: [
    { name: '斗宿', stars: 6, position: { x: 0.3, y: 0.6 }, color: '#FF5E5B', shape: 'square' },
    { name: '牛宿', stars: 6, position: { x: 0.25, y: 0.55 }, color: '#FFBD00', shape: 'line' },
    { name: '女宿', stars: 4, position: { x: 0.2, y: 0.5 }, color: '#EDFF00', shape: 'line' },
    { name: '虚宿', stars: 2, position: { x: 0.15, y: 0.45 }, color: '#7CFF00', shape: 'line' },
    { name: '危宿', stars: 3, position: { x: 0.1, y: 0.4 }, color: '#00FFC4', shape: 'triangle' },
    { name: '室宿', stars: 2, position: { x: 0.15, y: 0.35 }, color: '#00B8FF', shape: 'line' },
    { name: '壁宿', stars: 2, position: { x: 0.2, y: 0.3 }, color: '#7C00FF', shape: 'line' }
  ],
  // 西方白虎七宿
  baihu: [
    { name: '奎宿', stars: 16, position: { x: 0.2, y: 0.2 }, color: '#FF5E5B', shape: 'circle' },
    { name: '娄宿', stars: 3, position: { x: 0.25, y: 0.2 }, color: '#FFBD00', shape: 'line' },
    { name: '胃宿', stars: 3, position: { x: 0.3, y: 0.2 }, color: '#EDFF00', shape: 'line' },
    { name: '昴宿', stars: 7, position: { x: 0.35, y: 0.2 }, color: '#7CFF00', shape: 'cluster' },
    { name: '毕宿', stars: 8, position: { x: 0.4, y: 0.2 }, color: '#00FFC4', shape: 'triangle' },
    { name: '觜宿', stars: 3, position: { x: 0.45, y: 0.2 }, color: '#00B8FF', shape: 'triangle' },
    { name: '参宿', stars: 7, position: { x: 0.5, y: 0.2 }, color: '#7C00FF', shape: 'line' }
  ],
  // 南方朱雀七宿
  zhuque: [
    { name: '井宿', stars: 8, position: { x: 0.6, y: 0.2 }, color: '#FF5E5B', shape: 'square' },
    { name: '鬼宿', stars: 4, position: { x: 0.65, y: 0.2 }, color: '#FFBD00', shape: 'rectangle' },
    { name: '柳宿', stars: 8, position: { x: 0.7, y: 0.2 }, color: '#EDFF00', shape: 'line' },
    { name: '星宿', stars: 7, position: { x: 0.75, y: 0.2 }, color: '#7CFF00', shape: 'circle' },
    { name: '张宿', stars: 6, position: { x: 0.8, y: 0.2 }, color: '#00FFC4', shape: 'fan' },
    { name: '翼宿', stars: 22, position: { x: 0.8, y: 0.25 }, color: '#00B8FF', shape: 'wing' },
    { name: '轸宿', stars: 4, position: { x: 0.8, y: 0.3 }, color: '#7C00FF', shape: 'line' }
  ]
};

// 页面特定配置 - 基于四象
const pageConfigs = {
  login: {
    bgColor: '#050718',
    activeXiu: ['canglong'],
    starColor: 'rgba(255, 255, 255, 0.8)',
    fogColor: 'rgba(100, 100, 200, 0.2)',
    animationSpeed: 0.5,
    xiuIntensity: 1.0
  },
  dashboard: {
    bgColor: '#080828',
    activeXiu: ['canglong', 'baihu'],
    starColor: 'rgba(255, 240, 200, 0.9)',
    fogColor: 'rgba(150, 100, 200, 0.2)',
    animationSpeed: 0.7,
    xiuIntensity: 0.8
  },
  config: {
    bgColor: '#0a0a38',
    activeXiu: ['xuanwu'],
    starColor: 'rgba(200, 230, 255, 0.8)',
    fogColor: 'rgba(70, 120, 200, 0.2)',
    animationSpeed: 0.6,
    xiuIntensity: 0.9
  },
  baseline: {
    bgColor: '#100828',
    activeXiu: ['zhuque'],
    starColor: 'rgba(255, 220, 255, 0.8)',
    fogColor: 'rgba(180, 80, 180, 0.2)',
    animationSpeed: 0.5,
    xiuIntensity: 0.8
  },
  situation: {
    bgColor: '#081828',
    activeXiu: ['canglong', 'xuanwu', 'baihu', 'zhuque'],
    starColor: 'rgba(180, 255, 255, 0.9)',
    fogColor: 'rgba(80, 180, 180, 0.2)',
    animationSpeed: 0.8,
    xiuIntensity: 1.0
  },
  defense: {
    bgColor: '#180808',
    activeXiu: ['baihu'],
    starColor: 'rgba(255, 200, 200, 0.8)',
    fogColor: 'rgba(200, 80, 80, 0.2)',
    animationSpeed: 0.4,
    xiuIntensity: 1.0
  },
  av: {
    bgColor: '#181808',
    activeXiu: ['canglong', 'zhuque'],
    starColor: 'rgba(255, 255, 180, 0.9)',
    fogColor: 'rgba(200, 200, 80, 0.2)',
    animationSpeed: 0.6,
    xiuIntensity: 0.8
  },
  edge: {
    bgColor: '#082808',
    activeXiu: ['xuanwu', 'zhuque'],
    starColor: 'rgba(200, 255, 200, 0.8)',
    fogColor: 'rgba(80, 200, 80, 0.2)',
    animationSpeed: 0.7,
    xiuIntensity: 0.9
  }
};

// 获取当前页面配置
function getCurrentConfig() {
  return pageConfigs[currentPage] || pageConfigs.login;
}

function resize() {
  dpr = Math.min(window.devicePixelRatio || 1, 2);
  w = window.innerWidth; 
  h = window.innerHeight;
  canvas.width = Math.floor(w * dpr);
  canvas.height = Math.floor(h * dpr);
  canvas.style.width = w + 'px';
  canvas.style.height = h + 'px';
  
  // 重新初始化星空元素
  initStars();
  initFogEffects();
  initConstellations();
}

// 检测设备性能等级
function detectPerformance() {
  // 根据设备的处理器核心数和内存估计性能
  const cores = navigator.hardwareConcurrency || 4;
  const isLowEndDevice = cores <= 4;
  
  // 存储性能设置到localStorage以便下次使用
  if (!localStorage.getItem('bg_performance_mode')) {
    localStorage.setItem('bg_performance_mode', isLowEndDevice ? 'low' : 'high');
  }
  
  return isLowEndDevice || localStorage.getItem('bg_performance_mode') === 'low';
}

// 创建星星对象
function createStar() {
  const size = Math.random();
  return {
    x: Math.random() * w,
    y: Math.random() * h,
    size: size,
    brightness: 0.3 + Math.random() * 0.4,
    blinkSpeed: 0.01 + Math.random() * 0.03,
    blinkPhase: Math.random() * Math.PI * 2,
    moveSpeed: 0.01 + Math.random() * 0.04,
    angle: Math.random() * Math.PI * 2
  };
}

// 创建雾气对象
function createFog() {
  return {
    x: Math.random() * w,
    y: Math.random() * h,
    size: 300 + Math.random() * 500,
    alpha: 0.1 + Math.random() * 0.2,
    speedX: (Math.random() - 0.5) * 0.05,
    speedY: (Math.random() - 0.5) * 0.05,
    driftPhase: Math.random() * Math.PI * 2
  };
}

// 创建流星对象
function createShootingStarObj() {
  const speed = 8 + Math.random() * 12;
  const angle = Math.random() * Math.PI / 2 + Math.PI / 4;
  const length = 80 + Math.random() * 150;
  
  return {
    x: -100,
    y: Math.random() * h / 2,
    speed: speed,
    angle: angle,
    length: length,
    life: 1,
    decay: 0.01 + Math.random() * 0.02,
    color: Math.random() > 0.5 ? '#FFD700' : '#FFFFFF'
  };
}

// 创建对象池实例
const starPool = new ObjectPool(createStar, 2000);
const shootingStarPool = new ObjectPool(createShootingStarObj, 50);
const fogPool = new ObjectPool(createFog, 30);

// 初始化星星
function initStars() {
  // 回收当前星星到对象池
  stars.forEach(star => starPool.recycle(star));
  stars = [];
  
  // 根据设备性能调整星星数量
  const performanceFactor = detectPerformance() ? 0.7 : 1.0;
  const count = Math.floor((w * h) / 4000 * performanceFactor);
  
  // 批量创建星星，减少循环中的函数调用
  const batchSize = 100;
  for (let i = 0; i < count; i += batchSize) {
    const batchCount = Math.min(batchSize, count - i);
    for (let j = 0; j < batchCount; j++) {
      const star = starPool.get();
      // 重新初始化星星属性
      star.x = Math.random() * w;
      star.y = Math.random() * h;
      star.size = Math.random();
      star.brightness = 0.3 + Math.random() * 0.4;
      star.blinkSpeed = 0.01 + Math.random() * 0.03;
      star.blinkPhase = Math.random() * Math.PI * 2;
      star.moveSpeed = 0.01 + Math.random() * 0.04;
      star.angle = Math.random() * Math.PI * 2;
      stars.push(star);
    }
  }
}

// 初始化星宿星座
function initConstellations() {
  constellations = [];
  
  // 根据活动页面获取需要显示的星宿
  const config = getCurrentConfig();
  
  config.activeXiu.forEach(xiuGroup => {
    if (xiuData[xiuGroup]) {
      xiuData[xiuGroup].forEach(xiu => {
        const baseX = xiu.position.x * w;
        const baseY = xiu.position.y * h;
        const xiuStars = [];
        
        // 生成星宿内的星星
        for (let i = 0; i < xiu.stars; i++) {
          let starX, starY;
          
          // 根据不同形状生成星星位置
          switch (xiu.shape) {
            case 'triangle':
              const angle = (i / xiu.stars) * Math.PI * 2;
              const radius = 50 + Math.random() * 100;
              starX = baseX + Math.cos(angle) * radius;
              starY = baseY + Math.sin(angle) * radius;
              break;
            case 'line':
              const offset = (i / (xiu.stars - 1 || 1) - 0.5) * 200;
              starX = baseX + offset;
              starY = baseY + (Math.random() - 0.5) * 50;
              break;
            case 'circle':
              const circleAngle = (i / xiu.stars) * Math.PI * 2;
              const circleRadius = 80 + Math.random() * 40;
              starX = baseX + Math.cos(circleAngle) * circleRadius;
              starY = baseY + Math.sin(circleAngle) * circleRadius;
              break;
            case 'square':
              const side = Math.floor(i / 2);
              const pos = i % 2;
              const squareSize = 120;
              if (side === 0) {
                starX = baseX - squareSize + pos * squareSize * 2;
                starY = baseY - squareSize;
              } else {
                starX = baseX - squareSize + pos * squareSize * 2;
                starY = baseY + squareSize;
              }
              break;
            case 'rectangle':
              const rectSide = Math.floor(i / 2);
              const rectPos = i % 2;
              const rectWidth = 150;
              const rectHeight = 80;
              if (rectSide === 0) {
                starX = baseX - rectWidth + rectPos * rectWidth * 2;
                starY = baseY - rectHeight;
              } else {
                starX = baseX - rectWidth + rectPos * rectWidth * 2;
                starY = baseY + rectHeight;
              }
              break;
            case 'fan':
              const fanAngle = (i / xiu.stars) * Math.PI;
              const fanRadius = 50 + (i / xiu.stars) * 100;
              starX = baseX + Math.cos(fanAngle - Math.PI/2) * fanRadius;
              starY = baseY + Math.sin(fanAngle - Math.PI/2) * fanRadius;
              break;
            case 'cluster':
              starX = baseX + (Math.random() - 0.5) * 100;
              starY = baseY + (Math.random() - 0.5) * 100;
              break;
            case 'wing':
              const wingSide = i % 2;
              const wingAngle = ((i / 2) / (xiu.stars / 2)) * Math.PI/2;
              const wingRadius = 80 + ((i / 2) / (xiu.stars / 2)) * 120;
              const wingDir = wingSide === 0 ? 1 : -1;
              starX = baseX + Math.cos(wingAngle * wingDir) * wingRadius;
              starY = baseY + Math.sin(wingAngle) * wingRadius;
              break;
            default:
              starX = baseX + (Math.random() - 0.5) * 150;
              starY = baseY + (Math.random() - 0.5) * 150;
          }
          
          xiuStars.push({
            x: starX,
            y: starY,
            size: 1 + Math.random() * 2,
            brightness: 0.8 + Math.random() * 0.2,
            pulseSpeed: 0.02 + Math.random() * 0.04,
            pulsePhase: Math.random() * Math.PI * 2,
            color: xiu.color
          });
        }
        
        constellations.push({
          name: xiu.name,
          group: xiuGroup,
          stars: xiuStars,
          color: xiu.color,
          shape: xiu.shape,
          basePosition: { x: baseX, y: baseY },
          rotation: 0,
          rotationSpeed: (Math.random() - 0.5) * 0.0005,
          pulsePhase: Math.random() * Math.PI * 2
        });
      });
    }
  });
}

// 初始化雾气效果
function initFogEffects() {
  // 回收当前雾气到对象池
  fogEffects.forEach(fog => fogPool.recycle(fog));
  fogEffects = [];
  
  const count = detectPerformance() ? 3 : 5;
  for (let i = 0; i < count; i++) {
    const fog = fogPool.get();
    // 重新初始化雾气属性
    fog.x = Math.random() * w;
    fog.y = Math.random() * h;
    fog.size = 300 + Math.random() * 500;
    fog.alpha = 0.1 + Math.random() * 0.2;
    fog.speedX = (Math.random() - 0.5) * 0.05;
    fog.speedY = (Math.random() - 0.5) * 0.05;
    fog.driftPhase = Math.random() * Math.PI * 2;
    fogEffects.push(fog);
  }
}

// 生成流星
function createShootingStar() {
  if (Math.random() > 0.002) return; // 低概率生成
  
  const shootingStar = shootingStarPool.get();
  // 重新初始化流星属性
  shootingStar.x = -100;
  shootingStar.y = Math.random() * h / 2;
  shootingStar.speed = 8 + Math.random() * 12;
  shootingStar.angle = Math.random() * Math.PI / 2 + Math.PI / 4;
  shootingStar.length = 80 + Math.random() * 150;
  shootingStar.life = 1;
  shootingStar.decay = 0.01 + Math.random() * 0.02;
  shootingStar.color = Math.random() > 0.5 ? '#FFD700' : '#FFFFFF';
  
  shootingStars.push(shootingStar);
}

// 绘制星星
function drawStars(config, time) {
  const { starColor } = config;
  
  stars.forEach(star => {
    // 更新星星位置
    star.x += Math.cos(star.angle) * star.moveSpeed * config.animationSpeed;
    star.y += Math.sin(star.angle) * star.moveSpeed * config.animationSpeed;
    
    // 边界处理
    if (star.x < -10 || star.x > w + 10) star.x = (star.x + w + 20) % (w + 20) - 10;
    if (star.y < -10 || star.y > h + 10) star.y = (star.y + h + 20) % (h + 20) - 10;
    
    // 闪烁效果
    star.blinkPhase += star.blinkSpeed;
    const brightness = star.brightness * (0.7 + 0.3 * Math.sin(star.blinkPhase));
    
    // 根据大小设置不同效果
    if (star.size < 0.3) {
      // 小星星 - 简单点
      ctx.globalAlpha = brightness * 0.8;
      ctx.fillStyle = starColor;
      ctx.fillRect(star.x, star.y, 1, 1);
    } else if (star.size < 0.7) {
      // 中等星星 - 带发光效果
      ctx.globalAlpha = brightness * 0.5;
      ctx.beginPath();
      ctx.arc(star.x, star.y, star.size * 2, 0, Math.PI * 2);
      ctx.fillStyle = starColor;
      ctx.fill();
      
      ctx.globalAlpha = brightness;
      ctx.beginPath();
      ctx.arc(star.x, star.y, star.size, 0, Math.PI * 2);
      ctx.fill();
    } else {
      // 大星星 - 更强的发光效果
      ctx.globalAlpha = brightness * 0.3;
      ctx.beginPath();
      ctx.arc(star.x, star.y, star.size * 3, 0, Math.PI * 2);
      ctx.fillStyle = starColor;
      ctx.fill();
      
      ctx.globalAlpha = brightness * 0.6;
      ctx.beginPath();
      ctx.arc(star.x, star.y, star.size * 1.5, 0, Math.PI * 2);
      ctx.fill();
      
      ctx.globalAlpha = brightness;
      ctx.beginPath();
      ctx.arc(star.x, star.y, star.size, 0, Math.PI * 2);
      ctx.fill();
    }
  });
  
  ctx.globalAlpha = 1;
}

// 绘制星宿星座
function drawConstellations(config) {
  const { xiuIntensity } = config;
  
  constellations.forEach(constellation => {
    // 更新星座旋转
    constellation.rotation += constellation.rotationSpeed * config.animationSpeed;
    constellation.pulsePhase += 0.01 * config.animationSpeed;
    
    const pulseEffect = 0.8 + 0.2 * Math.sin(constellation.pulsePhase);
    
    ctx.save();
    ctx.translate(constellation.basePosition.x, constellation.basePosition.y);
    ctx.rotate(constellation.rotation);
    
    // 绘制星连线 - 降低透明度以提高内容可读性
    ctx.globalAlpha = 0.1 * xiuIntensity * pulseEffect; // 降低连线透明度
    ctx.strokeStyle = constellation.color;
    ctx.lineWidth = 0.6; // 减少线宽
    ctx.beginPath();
    
    const localStars = constellation.stars.map(star => ({
      x: star.x - constellation.basePosition.x,
      y: star.y - constellation.basePosition.y
    }));
    
    // 根据形状绘制连线
    if (constellation.shape === 'line' || constellation.shape === 'triangle' || 
        constellation.shape === 'square' || constellation.shape === 'rectangle') {
      // 按顺序连线
      localStars.forEach((star, index) => {
        if (index === 0) {
          ctx.moveTo(star.x, star.y);
        } else {
          ctx.lineTo(star.x, star.y);
        }
      });
      
      // 对于闭合形状
      if (constellation.shape === 'triangle' || 
          constellation.shape === 'square' || 
          constellation.shape === 'rectangle') {
        ctx.closePath();
      }
    } else if (constellation.shape === 'circle' || constellation.shape === 'fan') {
      // 对于圆形和扇形，按角度顺序连线
      localStars.sort((a, b) => {
        const angleA = Math.atan2(a.y, a.x);
        const angleB = Math.atan2(b.y, b.x);
        return angleA - angleB;
      });
      
      localStars.forEach((star, index) => {
        if (index === 0) {
          ctx.moveTo(star.x, star.y);
        } else {
          ctx.lineTo(star.x, star.y);
        }
      });
      
      if (constellation.shape === 'circle') {
        ctx.closePath();
      }
    }
    
    ctx.stroke();
    ctx.restore();
    
    // 绘制星座内的星星
    constellation.stars.forEach(star => {
      star.pulsePhase += star.pulseSpeed * config.animationSpeed;
      const pulse = 0.8 + 0.5 * Math.sin(star.pulsePhase);
      
      // 发光效果
      ctx.globalAlpha = 0.3 * xiuIntensity * pulse;
      ctx.beginPath();
      ctx.arc(star.x, star.y, star.size * 3, 0, Math.PI * 2);
      ctx.fillStyle = star.color;
      ctx.fill();
      
      ctx.globalAlpha = 0.7 * xiuIntensity * pulse;
      ctx.beginPath();
      ctx.arc(star.x, star.y, star.size * 1.5, 0, Math.PI * 2);
      ctx.fill();
      
      ctx.globalAlpha = 1.0 * xiuIntensity * pulse;
      ctx.beginPath();
      ctx.arc(star.x, star.y, star.size, 0, Math.PI * 2);
      ctx.fillStyle = star.color;
      ctx.fill();
    });
  });
  
  ctx.globalAlpha = 1;
}

// 绘制雾气效果
function drawFogEffects(config) {
  const { fogColor } = config;
  
  fogEffects.forEach(fog => {
    // 更新雾气位置和漂移
    fog.driftPhase += 0.002 * config.animationSpeed;
    const driftX = Math.cos(fog.driftPhase) * 0.2;
    const driftY = Math.sin(fog.driftPhase) * 0.2;
    
    fog.x += (fog.speedX + driftX) * config.animationSpeed;
    fog.y += (fog.speedY + driftY) * config.animationSpeed;
    
    // 边界循环
    if (fog.x < -fog.size) fog.x = w + fog.size;
    if (fog.x > w + fog.size) fog.x = -fog.size;
    if (fog.y < -fog.size) fog.y = h + fog.size;
    if (fog.y > h + fog.size) fog.y = -fog.size;
    
    // 绘制雾气 - 降低透明度以提高内容可读性
    ctx.save();
    ctx.globalCompositeOperation = 'lighter';
    
    const gradient = ctx.createRadialGradient(
      fog.x, fog.y, 0,
      fog.x, fog.y, fog.size
    );
    // 降低雾气透明度
    gradient.addColorStop(0, `${fogColor.replace('0.2', (fog.alpha * 0.4).toFixed(2))}`);
    gradient.addColorStop(0.5, `${fogColor.replace('0.2', (fog.alpha * 0.2).toFixed(2))}`);
    gradient.addColorStop(1, `${fogColor.replace('0.2', '0')}`);
    
    ctx.fillStyle = gradient;
    ctx.beginPath();
    ctx.arc(fog.x, fog.y, fog.size, 0, Math.PI * 2);
    ctx.fill();
    
    ctx.restore();
  });
}

// 绘制流星
function drawShootingStars(config) {
  shootingStars = shootingStars.filter(star => {
    // 更新流星位置
    star.x += Math.cos(star.angle) * star.speed * config.animationSpeed;
    star.y += Math.sin(star.angle) * star.speed * config.animationSpeed;
    star.life -= star.decay;
    
    // 绘制流星
    if (star.life > 0) {
      ctx.save();
      ctx.globalCompositeOperation = 'lighter';
      
      // 流星轨迹
      const tailX = star.x - Math.cos(star.angle) * star.length;
      const tailY = star.y - Math.sin(star.angle) * star.length;
      
      const gradient = ctx.createLinearGradient(star.x, star.y, tailX, tailY);
      gradient.addColorStop(0, `${star.color}${Math.floor(star.life * 255).toString(16).padStart(2, '0')}`);
      gradient.addColorStop(0.3, `${star.color}${Math.floor(star.life * 128).toString(16).padStart(2, '0')}`);
      gradient.addColorStop(1, 'transparent');
      
      ctx.strokeStyle = gradient;
      ctx.lineWidth = 1 + star.life * 2;
      ctx.lineCap = 'round';
      ctx.globalAlpha = star.life;
      
      ctx.beginPath();
      ctx.moveTo(star.x, star.y);
      ctx.lineTo(tailX, tailY);
      ctx.stroke();
      
      // 流星头部
      ctx.globalAlpha = star.life * 1.5;
      ctx.fillStyle = star.color;
      ctx.beginPath();
      ctx.arc(star.x, star.y, 1 + star.life, 0, Math.PI * 2);
      ctx.fill();
      
      ctx.restore();
      return true;
    }
    return false;
  });
}

// 性能监控变量
let frameCount = 0;
let lastFpsUpdate = 0;
let currentFps = 60;
let shouldOptimize = false;

// 主渲染循环
let lastTime = 0;
function step(currentTime = 0) {
  const deltaTime = currentTime - lastTime;
  lastTime = currentTime;
  
  // 计算FPS
  frameCount++;
  if (currentTime - lastFpsUpdate > 1000) {
    currentFps = Math.round((frameCount * 1000) / (currentTime - lastFpsUpdate));
    frameCount = 0;
    lastFpsUpdate = currentTime;
    
    // 根据FPS动态调整性能设置
    shouldOptimize = currentFps < 45;
  }
  
  const config = getCurrentConfig();
  
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.save();
  ctx.scale(dpr, dpr);
  
  // 绘制背景，增加深色渐变以提高前景内容可读性
  const bgGradient = ctx.createRadialGradient(
    w / 2, h / 2,
    0,
    w / 2, h / 2,
    Math.max(w, h)
  );
  bgGradient.addColorStop(0, `${config.bgColor}CC`); // 80% opacity
  bgGradient.addColorStop(1, `${config.bgColor}`); // 100% opacity
  ctx.fillStyle = bgGradient;
  ctx.fillRect(0, 0, w, h);
  
  // 根据性能动态调整渲染质量
  const renderQuality = shouldOptimize ? 0.5 : 1.0;
  
  // 绘制雾气效果（降低频率以提高性能）
  if (!shouldOptimize || frameCount % 3 === 0) {
    drawFogEffects(config);
  }
  
  // 绘制基础星星（跳过部分帧以提高性能）
  if (!shouldOptimize || frameCount % 2 === 0) {
    drawStars(config, currentTime);
  }
  
  // 绘制星宿星座（性能优化版本）
  if (!shouldOptimize || frameCount % 2 === 0) {
    drawConstellations(config);
  } else {
    // 低性能模式下简化星座绘制
    constellations.slice(0, Math.floor(constellations.length * 0.7)).forEach(constellation => {
      constellation.stars.forEach(star => {
        ctx.globalAlpha = 0.8;
        ctx.fillStyle = star.color;
        ctx.beginPath();
        ctx.arc(star.x, star.y, star.size * 0.8, 0, Math.PI * 2);
        ctx.fill();
      });
    });
    ctx.globalAlpha = 1;
  }
  
  // 创建并绘制流星
  createShootingStar();
  drawShootingStars(config);
  
  ctx.restore();
  requestAnimationFrame(step);
}

// 导出更新页面的函数，供app.js调用
window.updateBackgroundForPage = function(pageName) {
  // 平滑过渡效果
  const oldPage = currentPage;
  currentPage = pageName;
  
  if (pageConfigs[pageName]) {
    console.log(`切换背景效果到页面: ${pageName}，显示星宿: ${pageConfigs[pageName].activeXiu.join(', ')}`);
    
    // 重新初始化星座，以适应新页面的星宿配置
    initConstellations();
    
    // 可以在这里添加页面切换的动画效果
    const fadeDuration = 500; // 毫秒
    const startTime = Date.now();
    
    // 渐变过渡效果
    const animateTransition = () => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / fadeDuration, 1);
      
      // 这里可以添加更多的过渡效果逻辑
      
      if (progress < 1) {
        requestAnimationFrame(animateTransition);
      }
    };
    
    animateTransition();
  }
};

// 初始化
window.addEventListener('resize', debounce(resize, 250));
resize();
requestAnimationFrame(step);

