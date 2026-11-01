"use strict";

// 案内役のキャラクター「まもりん」(柴犬の道場生)。画面の右下で吹き出しを出して話す。
//   Mascot.say(text, mood)  mood: "normal" | "happy" | "worried" | "surprised"
//   Mascot.celebrate()      紙吹雪を降らせて喜ぶ

const Mascot = (() => {
  const eyes = {
    normal: `<circle cx="45" cy="62" r="4.2" fill="#2b2d42"/><circle cx="75" cy="62" r="4.2" fill="#2b2d42"/>
             <circle cx="46.4" cy="60.6" r="1.4" fill="#fff"/><circle cx="76.4" cy="60.6" r="1.4" fill="#fff"/>`,
    happy: `<path d="M39 63 q6 -7 12 0" stroke="#2b2d42" stroke-width="3" fill="none" stroke-linecap="round"/>
            <path d="M69 63 q6 -7 12 0" stroke="#2b2d42" stroke-width="3" fill="none" stroke-linecap="round"/>`,
    worried: `<circle cx="45" cy="63" r="3.6" fill="#2b2d42"/><circle cx="75" cy="63" r="3.6" fill="#2b2d42"/>
              <path d="M39 57 L50 52.5" stroke="#7a4a1d" stroke-width="2.5" stroke-linecap="round"/>
              <path d="M81 57 L70 52.5" stroke="#7a4a1d" stroke-width="2.5" stroke-linecap="round"/>`,
    surprised: `<circle cx="45" cy="62" r="5.5" fill="#2b2d42"/><circle cx="75" cy="62" r="5.5" fill="#2b2d42"/>
                <circle cx="47" cy="60" r="1.8" fill="#fff"/><circle cx="77" cy="60" r="1.8" fill="#fff"/>`,
  };
  // 口元は柴犬らしく、鼻から下に伸びる線と ω の形
  const mouths = {
    normal: `<path d="M60 81 v3.5 M52.5 84 q3.75 4.5 7.5 0 q3.75 4.5 7.5 0" stroke="#2b2d42" stroke-width="2.2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>`,
    happy: `<path d="M60 81 v3" stroke="#2b2d42" stroke-width="2.2" stroke-linecap="round"/>
            <path d="M51 84 q9 15 18 0 z" fill="#e5737f" stroke="#2b2d42" stroke-width="2" stroke-linejoin="round"/>
            <path d="M56 90 q4 3 8 0" stroke="#c94f5d" stroke-width="1.4" fill="none" stroke-linecap="round"/>`,
    worried: `<path d="M60 81 v3.5 M53 90 q7 -5 14 0" stroke="#2b2d42" stroke-width="2.2" fill="none" stroke-linecap="round"/>`,
    surprised: `<path d="M60 81 v2.5" stroke="#2b2d42" stroke-width="2.2" stroke-linecap="round"/>
                <ellipse cx="60" cy="88.5" rx="3.6" ry="4.4" fill="#e5737f" stroke="#2b2d42" stroke-width="2"/>`,
  };

  // 柴犬の特徴: 小さめで外向きの三角の耳、頬から口元にかけての白い毛 (裏白)、目の上の白い点 (麻呂眉)、
  // 前に出た口元 (マズル) と大きな黒い鼻
  function svg(mood = "normal") {
    return `<svg viewBox="0 0 120 120" width="96" height="96" role="img" aria-hidden="true">
      <path d="M17 52 Q15 24 29 12 Q42 21 50 34 Z" fill="#e8913a" stroke="#c8732a" stroke-width="1.5" stroke-linejoin="round"/>
      <path d="M24 45 Q24 28 30 20 Q38 27 43 35 Z" fill="#fbd3a5"/>
      <path d="M103 52 Q105 24 91 12 Q78 21 70 34 Z" fill="#e8913a" stroke="#c8732a" stroke-width="1.5" stroke-linejoin="round"/>
      <path d="M96 45 Q96 28 90 20 Q82 27 77 35 Z" fill="#fbd3a5"/>
      <path d="M60 28 C88 28 106 44 106 68 C106 90 86 104 60 104 C34 104 14 90 14 68 C14 44 32 28 60 28 Z" fill="#f2a65a"/>
      <path d="M15 74 C22 100 42 104 60 104 C78 104 98 100 105 74 C96 66 84 66 76 73 C70 68 64 67 60 70 C56 67 50 68 44 73 C36 66 24 66 15 74 Z" fill="#fff6ea"/>
      <ellipse cx="60" cy="82" rx="15" ry="11" fill="#fffaf3" stroke="#f0d9bf" stroke-width="1"/>
      <ellipse cx="44" cy="53" rx="5" ry="3.2" fill="#fff6ea"/>
      <ellipse cx="76" cy="53" rx="5" ry="3.2" fill="#fff6ea"/>
      <rect x="16" y="35" width="88" height="9" rx="4" fill="#e63946"/>
      <path d="M102 38 l14 -6 l-3 10 z M102 41 l13 6 l-9 3 z" fill="#e63946"/>
      <text x="60" y="43" font-size="8" text-anchor="middle" fill="#fff" font-weight="700">守</text>
      ${eyes[mood] || eyes.normal}
      <path d="M52.5 74.5 Q60 71 67.5 74.5 Q66 80.5 60 82 Q54 80.5 52.5 74.5 Z" fill="#2b2d42"/>
      <ellipse cx="57.5" cy="74.8" rx="2.4" ry="1.2" fill="#fff" opacity=".7"/>
      ${mouths[mood] || mouths.normal}
      <ellipse cx="31" cy="80" rx="6" ry="3.6" fill="#ff8fa3" opacity=".5"/>
      <ellipse cx="89" cy="80" rx="6" ry="3.6" fill="#ff8fa3" opacity=".5"/>
      <path d="M84 92 h22 v9 q0 11 -11 15 q-11 -4 -11 -15 z" fill="#4fb3ff" stroke="#1b6fa8" stroke-width="2"/>
      <path d="M89 102 l4 4 l8 -8" stroke="#fff" stroke-width="2.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
  }

  let root, bubble, face, hidden = false, tipIndex = 0, tips = () => [];

  function mount({ name, toggleLabel, tipTexts }) {
    tips = tipTexts;
    root = document.createElement("div");
    root.className = "mascot";
    root.innerHTML = `
      <div class="mascot-bubble" role="status" aria-live="polite"><strong class="mascot-name"></strong><span class="mascot-text"></span></div>
      <button class="mascot-face" type="button"></button>
      <button class="mascot-hide" type="button">×</button>`;
    document.body.appendChild(root);
    bubble = root.querySelector(".mascot-text");
    face = root.querySelector(".mascot-face");
    root.querySelector(".mascot-name").textContent = name;
    face.innerHTML = svg();
    face.setAttribute("aria-label", name);
    face.addEventListener("click", () => {
      if (hidden) return toggle();
      const list = tips();
      say(list[tipIndex++ % list.length], "happy");
    });
    root.querySelector(".mascot-hide").setAttribute("aria-label", toggleLabel);
    root.querySelector(".mascot-hide").addEventListener("click", toggle);
  }

  function rename(name, toggleLabel) {
    if (!root) return;
    root.querySelector(".mascot-name").textContent = name;
    face.setAttribute("aria-label", name);
    root.querySelector(".mascot-hide").setAttribute("aria-label", toggleLabel);
  }

  function toggle() {
    hidden = !hidden;
    root.classList.toggle("hidden", hidden);
  }

  function say(text, mood = "normal") {
    if (!root || !text) return;
    bubble.textContent = text;
    face.innerHTML = svg(mood);
    root.classList.remove("pop");
    void root.offsetWidth; // アニメーションをやり直す
    root.classList.add("pop");
  }

  function celebrate() {
    const colors = ["#4fb3ff", "#4cd2a0", "#ffc857", "#ff6b6b", "#c792ea", "#ff8fa3"];
    const layer = document.createElement("div");
    layer.className = "confetti";
    for (let i = 0; i < 90; i++) {
      const p = document.createElement("span");
      p.style.left = `${Math.random() * 100}%`;
      p.style.background = colors[i % colors.length];
      p.style.animationDelay = `${Math.random() * 0.6}s`;
      p.style.animationDuration = `${2 + Math.random() * 1.5}s`;
      p.style.transform = `rotate(${Math.random() * 360}deg)`;
      layer.appendChild(p);
    }
    document.body.appendChild(layer);
    setTimeout(() => layer.remove(), 4000);
    root?.classList.add("jump");
    setTimeout(() => root?.classList.remove("jump"), 1600);
  }

  return { mount, rename, say, celebrate, svg };
})();
