import { useEffect, useRef, useCallback, useState } from "react";
import {
  Application,
  Container,
  Graphics,
  Text,
  TextStyle,
  Sprite,
  Texture,
  Assets,
  AnimatedSprite,
  TextureStyle,
} from "pixi.js";
import type { Department, Agent, Task } from "../types";
import type { CliStatusMap } from "../types";
import { getCliStatus, getCliUsage, refreshCliUsage, type CliUsageEntry, type CliUsageWindow } from "../api";
import { useI18n, type UiLanguage } from "../i18n";

/* ================================================================== */
/*  Types                                                              */
/* ================================================================== */

interface SubAgent {
  id: string;
  parentAgentId: string;
  task: string;
  status: "working" | "done";
}

interface CrossDeptDelivery {
  id: string;
  fromAgentId: string;
  toAgentId: string;
}

interface CeoOfficeCall {
  id: string;
  fromAgentId: string;
  seatIndex: number;
  phase: "kickoff" | "review";
  action?: "arrive" | "speak";
  line?: string;
}

interface OfficeViewProps {
  departments: Department[];
  agents: Agent[];
  tasks: Task[];
  subAgents: SubAgent[];
  unreadAgentIds?: Set<string>;
  crossDeptDeliveries?: CrossDeptDelivery[];
  onCrossDeptDeliveryProcessed?: (id: string) => void;
  ceoOfficeCalls?: CeoOfficeCall[];
  onCeoOfficeCallProcessed?: (id: string) => void;
  onSelectAgent: (agent: Agent) => void;
  onSelectDepartment: (dept: Department) => void;
}

interface Delivery {
  sprite: Container;
  fromX: number;
  fromY: number;
  toX: number;
  toY: number;
  progress: number;
  arcHeight?: number;
  speed?: number;
  type?: "throw" | "walk";
  agentId?: string;
  holdAtSeat?: boolean;
  holdUntil?: number;
  arrived?: boolean;
}

interface RoomRect {
  dept: Department;
  x: number;
  y: number;
  w: number;
  h: number;
}

/* ================================================================== */
/*  Constants                                                          */
/* ================================================================== */

const MIN_OFFICE_W = 820;
const CEO_ZONE_H = 110;
const HALLWAY_H = 32;
const TARGET_CHAR_H = 52;
const MINI_CHAR_H = 28;
const CEO_SIZE = 44;
const DESK_W = 48;
const DESK_H = 26;
const SLOT_W = 100;
const SLOT_H = 120;
const COLS_PER_ROW = 3;
const ROOM_PAD = 16;
const TILE = 20;
const CEO_SPEED = 2.5;
const DELIVERY_SPEED = 0.012;

const BREAK_ROOM_H = 110;
const BREAK_ROOM_GAP = 16;

const BREAK_THEME = {
  floor1: 0x2a2218,
  floor2: 0x332a1e,
  wall: 0x6b5234,
  accent: 0xe8a849,
};

type SupportedLocale = UiLanguage;

const LOCALE_TEXT = {
  ceoOffice: {
    ko: "CEO 오피스",
    en: "CEO OFFICE",
    ja: "CEOオフィス",
    zh: "CEO办公室",
  },
  collabTable: {
    ko: "6인 협업 테이블",
    en: "6P COLLAB TABLE",
    ja: "6人コラボテーブル",
    zh: "6人协作桌",
  },
  statsEmployees: { ko: "직원", en: "Staff", ja: "スタッフ", zh: "员工" },
  statsWorking: { ko: "작업중", en: "Working", ja: "作業中", zh: "处理中" },
  statsProgress: { ko: "진행", en: "In Progress", ja: "進行", zh: "进行中" },
  statsDone: { ko: "완료", en: "Done", ja: "完了", zh: "已完成" },
  hint: {
    ko: "WASD/방향키: CEO 이동  |  Enter: 상호작용",
    en: "WASD/Arrow: CEO Move  |  Enter: Interact",
    ja: "WASD/矢印キー: CEO移動  |  Enter: 操作",
    zh: "WASD/方向键: CEO移动  |  Enter: 交互",
  },
  noAssignedAgent: {
    ko: "배정된 직원 없음",
    en: "No assigned staff",
    ja: "担当スタッフなし",
    zh: "暂无分配员工",
  },
  breakRoom: {
    ko: "☕ 휴게실",
    en: "☕ Break Room",
    ja: "☕ 休憩室",
    zh: "☕ 休息室",
  },
  role: {
    team_leader: { ko: "팀장", en: "Lead", ja: "リーダー", zh: "组长" },
    senior: { ko: "시니어", en: "Senior", ja: "シニア", zh: "资深" },
    junior: { ko: "주니어", en: "Junior", ja: "ジュニア", zh: "初级" },
    intern: { ko: "인턴", en: "Intern", ja: "インターン", zh: "实习" },
    part_time: { ko: "알바", en: "Part-time", ja: "アルバイト", zh: "兼职" },
  },
  partTime: {
    ko: "알바",
    en: "Part-time",
    ja: "アルバイト",
    zh: "兼职",
  },
  collabBadge: {
    ko: "🤝 협업",
    en: "🤝 Collaboration",
    ja: "🤝 協業",
    zh: "🤝 协作",
  },
  meetingBadgeKickoff: {
    ko: "📣 회의",
    en: "📣 Meeting",
    ja: "📣 会議",
    zh: "📣 会议",
  },
  meetingBadgeReview: {
    ko: "✅ 승인",
    en: "✅ Approval",
    ja: "✅ 承認",
    zh: "✅ 审批",
  },
  kickoffLines: {
    ko: [
      "유관부서 영향도 확인중",
      "리스크/의존성 공유중",
      "일정/우선순위 조율중",
      "담당 경계 정의중",
    ],
    en: [
      "Checking cross-team impact",
      "Sharing risks/dependencies",
      "Aligning schedule/priorities",
      "Defining ownership boundaries",
    ],
    ja: [
      "関連部署への影響を確認中",
      "リスク/依存関係を共有中",
      "日程/優先度を調整中",
      "担当境界を定義中",
    ],
    zh: [
      "正在确认跨团队影响",
      "正在共享风险/依赖关系",
      "正在协调排期/优先级",
      "正在定义职责边界",
    ],
  },
  reviewLines: {
    ko: [
      "보완사항 반영 확인중",
      "최종안 Approved 검토중",
      "수정 아이디어 공유중",
      "결과물 교차 검토중",
    ],
    en: [
      "Verifying follow-up updates",
      "Reviewing final approval draft",
      "Sharing revision ideas",
      "Cross-checking deliverables",
    ],
    ja: [
      "補完事項の反映を確認中",
      "最終承認案を確認中",
      "修正アイデアを共有中",
      "成果物を相互レビュー中",
    ],
    zh: [
      "正在确认补充项是否反映",
      "正在审阅最终审批方案",
      "正在共享修改思路",
      "正在交叉评审交付物",
    ],
  },
  cliUsageTitle: {
    ko: "CLI 사용량",
    en: "CLI Usage",
    ja: "CLI使用量",
    zh: "CLI 使用量",
  },
  cliConnected: {
    ko: "연결됨",
    en: "connected",
    ja: "接続中",
    zh: "已连接",
  },
  cliRefreshTitle: {
    ko: "사용량 새로고침",
    en: "Refresh usage data",
    ja: "使用量を更新",
    zh: "刷新用量数据",
  },
  cliNotSignedIn: {
    ko: "로그인되지 않음",
    en: "not signed in",
    ja: "未サインイン",
    zh: "未登录",
  },
  cliNoApi: {
    ko: "사용량 API 없음",
    en: "no usage API",
    ja: "使用量APIなし",
    zh: "无用量 API",
  },
  cliUnavailable: {
    ko: "사용 불가",
    en: "unavailable",
    ja: "利用不可",
    zh: "不可用",
  },
  cliLoading: {
    ko: "불러오는 중...",
    en: "loading...",
    ja: "読み込み中...",
    zh: "加载中...",
  },
  cliResets: {
    ko: "리셋까지",
    en: "resets",
    ja: "リセットまで",
    zh: "重置剩余",
  },
  cliNoData: {
    ko: "데이터 없음",
    en: "no data",
    ja: "データなし",
    zh: "无数据",
  },
  soon: {
    ko: "곧",
    en: "soon",
    ja: "まもなく",
    zh: "即将",
  },
};

const BREAK_CHAT_MESSAGES: Record<SupportedLocale, string[]> = {
  ko: [
    "커피 한 잔 더~", "오늘 점심 뭐 먹지?", "아 졸려...",
    "주말에 뭐 해?", "이번 프로젝트 힘들다ㅋ", "카페라떼 최고!",
    "오늘 날씨 좋다~", "야근 싫어ㅠ", "맛있는 거 먹고 싶다",
    "조금만 쉬자~", "ㅋㅋㅋㅋ", "간식 왔다!", "5분만 더~",
    "힘내자 파이팅!", "에너지 충전 중...", "집에 가고 싶다~",
  ],
  en: [
    "One more cup of coffee~", "What should we eat for lunch?", "So sleepy...",
    "Any weekend plans?", "This project is tough lol", "Cafe latte wins!",
    "Nice weather today~", "I hate overtime...", "Craving something tasty",
    "Let's take a short break~", "LOL", "Snacks are here!", "5 more minutes~",
    "Let's go, fighting!", "Recharging energy...", "I want to go home~",
  ],
  ja: [
    "コーヒーもう一杯~", "今日のランチ何にする?", "眠い...",
    "週末なにする?", "今回のプロジェクト大変w", "カフェラテ最高!",
    "今日の天気いいね~", "残業いやだ...", "おいしいもの食べたい",
    "ちょっと休もう~", "www", "おやつ来た!", "あと5分だけ~",
    "頑張ろう!", "エネルギー充電中...", "家に帰りたい~",
  ],
  zh: [
    "再来一杯咖啡~", "今天午饭吃什么?", "好困...",
    "周末准备做什么?", "这个项目有点难哈哈", "拿铁最棒!",
    "今天天气真好~", "不想加班...", "想吃点好吃的",
    "先休息一下吧~", "哈哈哈哈", "零食到了!", "再来5分钟~",
    "加油冲一波!", "正在补充能量...", "想回家了~",
  ],
};

function pickLocale<T>(locale: SupportedLocale, map: Record<SupportedLocale, T>): T {
  return map[locale] ?? map.ko;
}

// Break spots: positive x = offset from room left; negative x = offset from room right
// These are calibrated to match furniture positions drawn in buildScene
const BREAK_SPOTS = [
  { x: 86,  y: 72, dir: 'D' },   // 왼쪽 소파 좌측 (sofa at baseX+50, width 80)
  { x: 110, y: 72, dir: 'D' },   // 왼쪽 소파 중앙
  { x: 134, y: 72, dir: 'D' },   // 왼쪽 소파 우측
  { x: 30,  y: 58, dir: 'R' },   // 커피머신 앞 (machine at baseX, y+20)
  { x: -112, y: 72, dir: 'D' },  // 우측 소파 좌측 (sofa at rightX-120, width 80)
  { x: -82,  y: 72, dir: 'D' },  // 우측 소파 우측
  { x: -174, y: 56, dir: 'L' },  // 하이테이블 왼쪽 (table at rightX-170, width 36)
  { x: -144, y: 56, dir: 'R' },  // 하이테이블 오른쪽
];

const DEPT_THEME: Record<
  string,
  { floor1: number; floor2: number; wall: number; accent: number }
> = {
  dev: { floor1: 0x1e2d4a, floor2: 0x24365a, wall: 0x2a4a7a, accent: 0x3b82f6 },
  design: { floor1: 0x281e4a, floor2: 0x30265a, wall: 0x4a2a7a, accent: 0x8b5cf6 },
  planning: { floor1: 0x2e2810, floor2: 0x38321a, wall: 0x7a6a2a, accent: 0xf59e0b },
  operations: { floor1: 0x142e22, floor2: 0x1a382a, wall: 0x2a7a4a, accent: 0x10b981 },
  qa: { floor1: 0x2e1414, floor2: 0x381a1a, wall: 0x7a2a2a, accent: 0xef4444 },
  devsecops: { floor1: 0x2e1e0e, floor2: 0x382816, wall: 0x7a4a1a, accent: 0xf97316 },
};

function hashStr(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}

/* ================================================================== */
/*  Drawing helpers                                                    */
/* ================================================================== */

function drawTiledFloor(
  g: Graphics, x: number, y: number, w: number, h: number,
  c1: number, c2: number,
) {
  for (let ty = 0; ty < h; ty += TILE) {
    for (let tx = 0; tx < w; tx += TILE) {
      g.rect(x + tx, y + ty, TILE, TILE).fill(((tx / TILE + ty / TILE) & 1) === 0 ? c1 : c2);
    }
  }
}

function drawDesk(parent: Container, dx: number, dy: number, working: boolean) {
  const g = new Graphics();
  // Shadow
  g.ellipse(dx + DESK_W / 2, dy + DESK_H + 1, DESK_W / 2 + 1, 3).fill({ color: 0x000000, alpha: 0.15 });
  // Desk body
  g.roundRect(dx, dy, DESK_W, DESK_H, 2).fill(0xa0792c);
  g.roundRect(dx + 1, dy + 1, DESK_W - 2, DESK_H - 2, 1).fill(0xb8893c);
  // ── Keyboard at TOP (closest to character above) ──
  g.roundRect(dx + DESK_W / 2 - 8, dy + 2, 16, 5, 1).fill(0x3a3a4a);
  for (let r = 0; r < 2; r++) {
    for (let c = 0; c < 4; c++) {
      g.rect(dx + DESK_W / 2 - 6 + c * 3.5, dy + 2.8 + r * 2.2, 2.5, 1.5).fill(0x555568);
    }
  }
  // Paper stack (left)
  g.rect(dx + 3, dy + 2, 9, 10).fill(0xf5f0e0);
  g.rect(dx + 4, dy + 3, 9, 10).fill(0xfaf5ea);
  // Coffee mug (right)
  g.circle(dx + DESK_W - 8, dy + 7, 3.5).fill(0xeeeeee);
  g.circle(dx + DESK_W - 8, dy + 7, 2).fill(0x6b4226);
  // ── Monitor at BOTTOM (character looks down at it) ──
  const mx = dx + DESK_W / 2 - 8;
  const my = dy + DESK_H - 14;
  g.roundRect(mx, my, 16, 11, 1.5).fill(0x222233);
  g.roundRect(mx + 1.5, my + 1, 13, 8, 1).fill(working ? 0x4499ff : 0x1a1a28);
  if (working) {
    for (let i = 0; i < 3; i++) {
      g.moveTo(mx + 3.5, my + 2.5 + i * 2.2)
        .lineTo(mx + 3.5 + 4 + Math.random() * 4, my + 2.5 + i * 2.2)
        .stroke({ width: 0.7, color: 0xaaddff, alpha: 0.6 });
    }
  }
  // Monitor stand (below monitor)
  g.rect(mx + 6, my - 2, 4, 2).fill(0x444455);
  g.rect(mx + 4, my - 3, 8, 1.5).fill(0x555566);
  parent.addChild(g);
}

function drawChair(parent: Container, cx: number, cy: number, color: number) {
  const g = new Graphics();
  // Seat cushion (wide so it peeks out around the character)
  g.ellipse(cx, cy, 16, 10).fill({ color: 0x000000, alpha: 0.1 });
  g.ellipse(cx, cy, 15, 9).fill(color);
  g.ellipse(cx, cy, 15, 9).stroke({ width: 1, color: 0x000000, alpha: 0.12 });
  // Armrests (stick out on both sides)
  g.roundRect(cx - 17, cy - 6, 5, 14, 2).fill(color);
  g.roundRect(cx + 12, cy - 6, 5, 14, 2).fill(color);
  // Chair back (wide arc behind)
  g.roundRect(cx - 14, cy - 12, 28, 6, 4).fill(color);
  g.roundRect(cx - 14, cy - 12, 28, 6, 4).stroke({ width: 1, color: 0x000000, alpha: 0.1 });
  parent.addChild(g);
}

function drawPlant(parent: Container, x: number, y: number) {
  const g = new Graphics();
  g.roundRect(x - 4, y, 8, 6, 1.5).fill(0xcc6633);
  g.circle(x, y - 3, 5).fill(0x33aa44);
  g.circle(x - 3, y - 5, 3).fill(0x44bb55);
  g.circle(x + 3, y - 5, 3).fill(0x44bb55);
  g.circle(x, y - 7, 2.5).fill(0x55cc66);
  parent.addChild(g);
}

function drawWhiteboard(parent: Container, x: number, y: number) {
  const g = new Graphics();
  g.roundRect(x, y, 38, 22, 2).fill(0xcccccc);
  g.roundRect(x + 2, y + 2, 34, 18, 1).fill(0xf8f8f0);
  const cc = [0x3b82f6, 0xef4444, 0x22c55e, 0xf59e0b];
  for (let i = 0; i < 3; i++) {
    g.moveTo(x + 5, y + 5 + i * 5)
      .lineTo(x + 5 + 8 + Math.random() * 16, y + 5 + i * 5)
      .stroke({ width: 1, color: cc[i], alpha: 0.7 });
  }
  parent.addChild(g);
}

function drawBookshelf(parent: Container, x: number, y: number) {
  const g = new Graphics();
  g.roundRect(x, y, 28, 18, 2).fill(0x8b6914);
  g.rect(x + 1, y + 1, 26, 16).fill(0x654a0e);
  g.moveTo(x + 1, y + 9).lineTo(x + 27, y + 9).stroke({ width: 1, color: 0x8b6914 });
  const colors = [0xcc3333, 0x3366cc, 0x33aa55, 0xccaa33, 0x9944aa];
  for (let i = 0; i < 4; i++) {
    g.rect(x + 3 + i * 5.5, y + 2, 4, 6).fill(colors[i % colors.length]);
    g.rect(x + 3 + i * 6, y + 10, 4, 6).fill(colors[(i + 2) % colors.length]);
  }
  parent.addChild(g);
}

function drawCoffeeMachine(parent: Container, x: number, y: number) {
  const g = new Graphics();
  g.roundRect(x, y, 20, 28, 2).fill(0x555555);
  g.roundRect(x + 1, y + 1, 18, 26, 1).fill(0x666666);
  // buttons
  g.circle(x + 6, y + 6, 2).fill(0xff4444);
  g.circle(x + 14, y + 6, 2).fill(0x44ff44);
  // nozzle
  g.rect(x + 8, y + 12, 4, 6).fill(0x333333);
  // cup
  g.roundRect(x + 6, y + 20, 8, 6, 1).fill(0xffffff);
  g.rect(x + 7, y + 21, 6, 3).fill(0x6b4226);
  parent.addChild(g);
}

function drawSofa(parent: Container, x: number, y: number, color: number) {
  const g = new Graphics();
  // seat
  g.roundRect(x, y, 80, 18, 4).fill(color);
  g.roundRect(x + 2, y + 2, 76, 14, 3).fill(color + 0x111111);
  // backrest
  g.roundRect(x + 4, y - 8, 72, 10, 3).fill(color - 0x111111);
  // armrests
  g.roundRect(x - 4, y - 6, 8, 22, 3).fill(color - 0x080808);
  g.roundRect(x + 76, y - 6, 8, 22, 3).fill(color - 0x080808);
  // cushion lines
  g.moveTo(x + 27, y + 3).lineTo(x + 27, y + 15).stroke({ width: 0.8, color: 0x000000, alpha: 0.15 });
  g.moveTo(x + 53, y + 3).lineTo(x + 53, y + 15).stroke({ width: 0.8, color: 0x000000, alpha: 0.15 });
  parent.addChild(g);
}

function drawCoffeeTable(parent: Container, x: number, y: number) {
  const g = new Graphics();
  // table top (elliptical)
  g.ellipse(x + 18, y + 5, 18, 8).fill(0x8b6914);
  g.ellipse(x + 18, y + 5, 16, 6).fill(0xa0792c);
  // legs
  g.rect(x + 6, y + 10, 3, 8).fill(0x654a0e);
  g.rect(x + 27, y + 10, 3, 8).fill(0x654a0e);
  // coffee cup
  g.roundRect(x + 12, y + 1, 5, 4, 1).fill(0xffffff);
  g.rect(x + 13, y + 2, 3, 2).fill(0x6b4226);
  // snack plate
  g.ellipse(x + 24, y + 4, 4, 2.5).fill(0xeeeeee);
  g.circle(x + 23, y + 3.5, 1.5).fill(0xddaa44);
  g.circle(x + 25.5, y + 4, 1.5).fill(0xcc8833);
  parent.addChild(g);
}

function drawHighTable(parent: Container, x: number, y: number) {
  const g = new Graphics();
  // table top
  g.roundRect(x, y, 36, 14, 2).fill(0x8b6914);
  g.roundRect(x + 1, y + 1, 34, 12, 1).fill(0xa0792c);
  // legs
  g.rect(x + 4, y + 14, 3, 16).fill(0x654a0e);
  g.rect(x + 29, y + 14, 3, 16).fill(0x654a0e);
  // crossbar
  g.rect(x + 6, y + 24, 24, 2).fill(0x654a0e);
  parent.addChild(g);
}

function drawVendingMachine(parent: Container, x: number, y: number) {
  const g = new Graphics();
  g.roundRect(x, y, 22, 30, 2).fill(0x334455);
  g.roundRect(x + 1, y + 1, 20, 28, 1).fill(0x445566);
  // display rows of drinks
  const drinkColors = [0xff4444, 0x44aaff, 0x44ff44, 0xffaa33, 0xff66aa, 0x8844ff];
  for (let r = 0; r < 3; r++) {
    for (let c = 0; c < 3; c++) {
      g.roundRect(x + 3 + c * 6, y + 3 + r * 7, 4, 5, 1).fill(drinkColors[(r * 3 + c) % drinkColors.length]);
    }
  }
  // dispense slot
  g.roundRect(x + 4, y + 24, 14, 4, 1).fill(0x222233);
  parent.addChild(g);
}

/* ================================================================== */
/*  Helpers                                                            */
/* ================================================================== */

function formatReset(iso: string, locale: SupportedLocale): string {
  const diff = new Date(iso).getTime() - Date.now();
  if (diff <= 0) return pickLocale(locale, LOCALE_TEXT.soon);
  const h = Math.floor(diff / 3_600_000);
  const m = Math.floor((diff % 3_600_000) / 60_000);
  if (h > 0) {
    if (locale === "ko") return `${h}시간 ${m}분`;
    if (locale === "ja") return `${h}時間 ${m}分`;
    if (locale === "zh") return `${h}小时 ${m}分`;
    return `${h}h ${m}m`;
  }
  if (locale === "ko") return `${m}분`;
  if (locale === "ja") return `${m}分`;
  if (locale === "zh") return `${m}分`;
  return `${m}m`;
}

function formatPeopleCount(count: number, locale: SupportedLocale): string {
  if (locale === "ko") return `${count}명`;
  if (locale === "ja") return `${count}人`;
  if (locale === "zh") return `${count}人`;
  return `${count}`;
}

function formatTaskCount(count: number, locale: SupportedLocale): string {
  if (locale === "ko") return `${count}건`;
  if (locale === "ja") return `${count}件`;
  if (locale === "zh") return `${count}项`;
  return `${count}`;
}

/* ================================================================== */
/*  Main Component                                                     */
/* ================================================================== */

export default function OfficeView({
  departments, agents, tasks, subAgents,
  unreadAgentIds,
  crossDeptDeliveries,
  onCrossDeptDeliveryProcessed,
  ceoOfficeCalls,
  onCeoOfficeCallProcessed,
  onSelectAgent, onSelectDepartment,
}: OfficeViewProps) {
  const { language, t } = useI18n();
  const containerRef = useRef<HTMLDivElement>(null);
  const appRef = useRef<Application | null>(null);
  const texturesRef = useRef<Record<string, Texture>>({});
  const destroyedRef = useRef(false);
  const initDoneRef = useRef(false);

  // Animation state refs
  const tickRef = useRef(0);
  const keysRef = useRef<Record<string, boolean>>({});
  const ceoPosRef = useRef({ x: 180, y: 60 });
  const ceoSpriteRef = useRef<Container | null>(null);
  const crownRef = useRef<Text | null>(null);
  const highlightRef = useRef<Graphics | null>(null);
  const animItemsRef = useRef<Array<{
    sprite: Container; status: string;
    baseX: number; baseY: number; particles: Container;
  }>>([]);
  const roomRectsRef = useRef<RoomRect[]>([]);
  const deliveriesRef = useRef<Delivery[]>([]);
  const deliveryLayerRef = useRef<Container | null>(null);
  const prevAssignRef = useRef<Set<string>>(new Set());
  const agentPosRef = useRef<Map<string, { x: number; y: number }>>(new Map());
  const processedCrossDeptRef = useRef<Set<string>>(new Set());
  const processedCeoOfficeRef = useRef<Set<string>>(new Set());
  const spriteMapRef = useRef<Map<string, number>>(new Map());
  const ceoMeetingSeatsRef = useRef<Array<{ x: number; y: number }>>([]);
  const totalHRef = useRef(600);
  const officeWRef = useRef(MIN_OFFICE_W);
  const breakRoomRectRef = useRef<{ x: number; y: number; w: number; h: number } | null>(null);
  const breakAnimItemsRef = useRef<Array<{
    sprite: Container; baseX: number; baseY: number;
  }>>([]);
  const breakSteamParticlesRef = useRef<Container | null>(null);
  const breakBubblesRef = useRef<Container[]>([]);
  const localeRef = useRef<SupportedLocale>(language);
  localeRef.current = language;

  // Latest data via refs (avoids stale closures)
  const dataRef = useRef({ departments, agents, tasks, subAgents, unreadAgentIds });
  dataRef.current = { departments, agents, tasks, subAgents, unreadAgentIds };
  const cbRef = useRef({ onSelectAgent, onSelectDepartment });
  cbRef.current = { onSelectAgent, onSelectDepartment };

  /* ── BUILD SCENE (no app destroy, just stage clear + rebuild) ── */
  const buildScene = useCallback(() => {
    const app = appRef.current;
    const textures = texturesRef.current;
    if (!app) return;

    app.stage.removeChildren();
    animItemsRef.current = [];
    roomRectsRef.current = [];
    agentPosRef.current.clear();
    breakAnimItemsRef.current = [];
    breakBubblesRef.current = [];
    breakSteamParticlesRef.current = null;
    breakRoomRectRef.current = null;
    ceoMeetingSeatsRef.current = [];
    deliveriesRef.current = [];

    const { departments, agents, tasks, subAgents, unreadAgentIds: unread } = dataRef.current;
    const activeLocale = localeRef.current;

    // Assign unique sprite numbers to each agent (1-12, no duplicates)
    const spriteMap = new Map<string, number>();
    const allAgents = [...agents].sort((a, b) => a.id.localeCompare(b.id)); // stable order
    allAgents.forEach((a, i) => spriteMap.set(a.id, (i % 12) + 1));
    spriteMapRef.current = spriteMap;

    // Measure container width for responsive layout
    const OFFICE_W = officeWRef.current;

    // Layout: fit as many columns as possible (3 for 6 depts)
    const deptCount = departments.length || 1;
    const baseRoomW = COLS_PER_ROW * SLOT_W + ROOM_PAD * 2;
    const roomGap = 12;
    // Try 3 cols, fall back to 2, then 1
    let gridCols = Math.min(deptCount, 3);
    while (gridCols > 1 && (gridCols * baseRoomW + (gridCols - 1) * roomGap + 24) > OFFICE_W) {
      gridCols--;
    }
    const gridRows = Math.ceil(deptCount / gridCols);
    const agentsPerDept = departments.map(d => agents.filter(a => a.department_id === d.id));
    const maxAgents = Math.max(1, ...agentsPerDept.map(a => a.length));
    const agentRows = Math.ceil(maxAgents / COLS_PER_ROW);
    // Scale rooms to fill available width
    const totalRoomSpace = OFFICE_W - 24 - (gridCols - 1) * roomGap;
    const roomW = Math.max(baseRoomW, Math.floor(totalRoomSpace / gridCols));
    const roomH = Math.max(170, agentRows * SLOT_H + 44);
    const deptStartY = CEO_ZONE_H + HALLWAY_H;
    const breakRoomY = deptStartY + gridRows * (roomH + roomGap) + BREAK_ROOM_GAP;
    const totalH = breakRoomY + BREAK_ROOM_H + 30;
    const roomStartX = (OFFICE_W - (gridCols * roomW + (gridCols - 1) * roomGap)) / 2;
    totalHRef.current = totalH;

    app.renderer.resize(OFFICE_W, totalH);

    // ── BUILDING SHELL ──
    const bg = new Graphics();
    bg.roundRect(0, 0, OFFICE_W, totalH, 6).fill(0x12161f);
    bg.roundRect(0, 0, OFFICE_W, totalH, 6).stroke({ width: 3, color: 0x2a3040 });
    app.stage.addChild(bg);

    // ── CEO ZONE ──
    const ceoLayer = new Container();
    const ceoFloor = new Graphics();
    drawTiledFloor(ceoFloor, 4, 4, OFFICE_W - 8, CEO_ZONE_H - 4, 0x3a2e12, 0x443818);
    ceoLayer.addChild(ceoFloor);
    const ceoBorder = new Graphics();
    ceoBorder.roundRect(4, 4, OFFICE_W - 8, CEO_ZONE_H - 4, 3)
      .stroke({ width: 2, color: 0xd4a017 });
    ceoBorder.roundRect(3, 3, OFFICE_W - 6, CEO_ZONE_H - 2, 4)
      .stroke({ width: 1, color: 0xf5c842, alpha: 0.25 });
    ceoLayer.addChild(ceoBorder);

    const ceoLabel = new Text({
      text: pickLocale(activeLocale, LOCALE_TEXT.ceoOffice),
      style: new TextStyle({ fontSize: 10, fill: 0xf5c842, fontWeight: "bold", fontFamily: "monospace", letterSpacing: 2 }),
    });
    ceoLabel.position.set(12, 8);
    ceoLayer.addChild(ceoLabel);

    // CEO desk
    const cdx = 50, cdy = 28;
    const cdg = new Graphics();
    cdg.roundRect(cdx, cdy, 64, 34, 3).fill(0x5c3d0a);
    cdg.roundRect(cdx + 1, cdy + 1, 62, 32, 2).fill(0x8b6914);
    cdg.roundRect(cdx + 19, cdy + 2, 26, 16, 2).fill(0x222233);
    cdg.roundRect(cdx + 20.5, cdy + 3.5, 23, 12, 1).fill(0x335599);
    cdg.roundRect(cdx + 22, cdy + 24, 20, 7, 2).fill(0xd4a017);
    ceoLayer.addChild(cdg);
    const ceoPlateText = new Text({
      text: "CEO",
      style: new TextStyle({ fontSize: 5, fill: 0x000000, fontWeight: "bold", fontFamily: "monospace" }),
    });
    ceoPlateText.anchor.set(0.5, 0.5);
    ceoPlateText.position.set(cdx + 32, cdy + 27.5);
    ceoLayer.addChild(ceoPlateText);
    drawChair(ceoLayer, cdx + 32, cdy + 46, 0xb8860b);

    // 6-seat collaboration table in CEO OFFICE
    const mtW = 220;
    const mtH = 28;
    const mtX = Math.floor((OFFICE_W - mtW) / 2);
    const mtY = 48;
    const mt = new Graphics();
    mt.roundRect(mtX, mtY, mtW, mtH, 12).fill(0x6f4f1e);
    mt.roundRect(mtX + 3, mtY + 3, mtW - 6, mtH - 6, 10).fill(0x9d7440);
    mt.roundRect(mtX + 64, mtY + 8, 92, 12, 5).fill({ color: 0xf7d89a, alpha: 0.35 });
    ceoLayer.addChild(mt);

    const meetingSeatX = [mtX + 40, mtX + 110, mtX + 180];
    for (const sx of meetingSeatX) {
      drawChair(ceoLayer, sx, mtY - 4, 0x8a6230);
      drawChair(ceoLayer, sx, mtY + mtH + 10, 0x8a6230);
    }

    const meetingLabel = new Text({
      text: pickLocale(activeLocale, LOCALE_TEXT.collabTable),
      style: new TextStyle({ fontSize: 7, fill: 0xf4c862, fontWeight: "bold", fontFamily: "monospace", letterSpacing: 1 }),
    });
    meetingLabel.anchor.set(0.5, 0.5);
    meetingLabel.position.set(mtX + mtW / 2, mtY + mtH / 2);
    ceoLayer.addChild(meetingLabel);

    ceoMeetingSeatsRef.current = [
      { x: meetingSeatX[0], y: mtY + 2 },
      { x: meetingSeatX[1], y: mtY + 2 },
      { x: meetingSeatX[2], y: mtY + 2 },
      { x: meetingSeatX[0], y: mtY + mtH + 20 },
      { x: meetingSeatX[1], y: mtY + mtH + 20 },
      { x: meetingSeatX[2], y: mtY + mtH + 20 },
    ];

    // Stats panels (right side)
    const workingCount = agents.filter(a => a.status === "working").length;
    const doneCount = tasks.filter(t => t.status === "done").length;
    const inProg = tasks.filter(t => t.status === "in_progress").length;
    const stats = [
      {
        icon: "🤖",
        label: pickLocale(activeLocale, LOCALE_TEXT.statsEmployees),
        val: formatPeopleCount(agents.length, activeLocale),
      },
      {
        icon: "⚡",
        label: pickLocale(activeLocale, LOCALE_TEXT.statsWorking),
        val: formatPeopleCount(workingCount, activeLocale),
      },
      {
        icon: "📋",
        label: pickLocale(activeLocale, LOCALE_TEXT.statsProgress),
        val: formatTaskCount(inProg, activeLocale),
      },
      {
        icon: "✅",
        label: pickLocale(activeLocale, LOCALE_TEXT.statsDone),
        val: `${doneCount}/${tasks.length}`,
      },
    ];
    stats.forEach((s, i) => {
      const sx = OFFICE_W - 340 + i * 82, sy = 12;
      const sg = new Graphics();
      sg.roundRect(sx, sy, 74, 26, 4).fill({ color: 0xf5c842, alpha: 0.1 });
      sg.roundRect(sx, sy, 74, 26, 4).stroke({ width: 1, color: 0xf5c842, alpha: 0.25 });
      ceoLayer.addChild(sg);
      const ti = new Text({ text: s.icon, style: new TextStyle({ fontSize: 10 }) });
      ti.position.set(sx + 4, sy + 4);
      ceoLayer.addChild(ti);
      ceoLayer.addChild(Object.assign(new Text({
        text: s.label,
        style: new TextStyle({ fontSize: 7, fill: 0xd4a017, fontFamily: "monospace" }),
      }), { x: sx + 18, y: sy + 2 }));
      ceoLayer.addChild(Object.assign(new Text({
        text: s.val,
        style: new TextStyle({ fontSize: 10, fill: 0xffffff, fontWeight: "bold", fontFamily: "monospace" }),
      }), { x: sx + 18, y: sy + 13 }));
    });

    // Keyboard hint
    const hint = new Text({
      text: pickLocale(activeLocale, LOCALE_TEXT.hint),
      style: new TextStyle({
        fontSize: 10,
        fontWeight: "bold",
        fill: 0xd9c48a,
        fontFamily: "monospace",
      }),
    });
    hint.anchor.set(1, 1);
    // Keep the control hint inside the CEO OFFICE area (bottom-right corner).
    hint.position.set(OFFICE_W - 16, CEO_ZONE_H - 8);
    ceoLayer.addChild(hint);

    drawPlant(ceoLayer, 18, 62);
    drawPlant(ceoLayer, OFFICE_W - 22, 62);

    app.stage.addChild(ceoLayer);

    // ── HALLWAY ──
    const hallY = CEO_ZONE_H;
    const hallG = new Graphics();
    hallG.rect(4, hallY, OFFICE_W - 8, HALLWAY_H).fill(0x1a1e28);
    for (let dx = 20; dx < OFFICE_W - 20; dx += 16) {
      hallG.rect(dx, hallY + HALLWAY_H / 2, 6, 1).fill({ color: 0x444c5c, alpha: 0.3 });
    }
    app.stage.addChild(hallG);

    // ── DEPARTMENT ROOMS ──
    departments.forEach((dept, deptIdx) => {
      const col = deptIdx % gridCols;
      const row = Math.floor(deptIdx / gridCols);
      const rx = roomStartX + col * (roomW + roomGap);
      const ry = deptStartY + row * (roomH + roomGap);
      const theme = DEPT_THEME[dept.id] || DEPT_THEME.dev;
      roomRectsRef.current.push({ dept, x: rx, y: ry, w: roomW, h: roomH });

      const room = new Container();

      const floorG = new Graphics();
      drawTiledFloor(floorG, rx, ry, roomW, roomH, theme.floor1, theme.floor2);
      room.addChild(floorG);

      const wallG = new Graphics();
      wallG.roundRect(rx, ry, roomW, roomH, 3).stroke({ width: 2.5, color: theme.wall });
      room.addChild(wallG);

      // Door opening
      const doorG = new Graphics();
      doorG.rect(rx + roomW / 2 - 16, ry - 2, 32, 5).fill(0x12161f);
      room.addChild(doorG);

      // Sign
      const signW = 84;
      const signBg = new Graphics();
      signBg.roundRect(rx + roomW / 2 - signW / 2, ry - 4, signW, 18, 4).fill(theme.accent);
      signBg.eventMode = "static";
      signBg.cursor = "pointer";
      signBg.on("pointerdown", () => cbRef.current.onSelectDepartment(dept));
      room.addChild(signBg);
      const signTxt = new Text({
        text: `${dept.icon || "🏢"} ${activeLocale === "ko" ? (dept.name_ko || dept.name) : dept.name}`,
        style: new TextStyle({ fontSize: 9, fill: 0xffffff, fontWeight: "bold", fontFamily: "system-ui, sans-serif" }),
      });
      signTxt.anchor.set(0.5, 0.5);
      signTxt.position.set(rx + roomW / 2, ry + 5);
      room.addChild(signTxt);

      drawWhiteboard(room, rx + roomW - 48, ry + 18);
      drawBookshelf(room, rx + 6, ry + 18);
      drawPlant(room, rx + 8, ry + roomH - 14);
      drawPlant(room, rx + roomW - 12, ry + roomH - 14);

      // Agents (all dept members keep desks; break agents' sprites move to break room)
      const deptAgents = agents.filter(a => a.department_id === dept.id);
      if (deptAgents.length === 0) {
        const et = new Text({
          text: pickLocale(activeLocale, LOCALE_TEXT.noAssignedAgent),
          style: new TextStyle({ fontSize: 10, fill: 0x556677, fontFamily: "system-ui, sans-serif" }),
        });
        et.anchor.set(0.5, 0.5);
        et.position.set(rx + roomW / 2, ry + roomH / 2);
        room.addChild(et);
      }

      deptAgents.forEach((agent, agentIdx) => {
        const acol = agentIdx % COLS_PER_ROW;
        const arow = Math.floor(agentIdx / COLS_PER_ROW);
        const ax = rx + ROOM_PAD + acol * SLOT_W + SLOT_W / 2;
        const ay = ry + 38 + arow * SLOT_H;
        const isWorking = agent.status === "working";
        const isOffline = agent.status === "offline";
        const isBreak = agent.status === "break";

        // Layout (top→bottom): name+role → chair(behind) + character(↓) → desk
        const nameY = ay;
        const charFeetY = nameY + 24 + TARGET_CHAR_H; // feet position (anchor 0.5,1)
        const deskY = charFeetY - 8; // desk covers lower legs, upper body visible

        agentPosRef.current.set(agent.id, { x: ax, y: deskY });

        // ── Name tag (above character) ──
        const nt = new Text({
          text: activeLocale === "ko" ? (agent.name_ko || agent.name) : agent.name,
          style: new TextStyle({ fontSize: 7, fill: 0xffffff, fontWeight: "bold", fontFamily: "system-ui, sans-serif" }),
        });
        nt.anchor.set(0.5, 0);
        const ntW = nt.width + 6;
        const ntBg = new Graphics();
        ntBg.roundRect(ax - ntW / 2, nameY, ntW, 12, 3).fill({ color: 0x000000, alpha: 0.5 });
        room.addChild(ntBg);
        nt.position.set(ax, nameY + 2);
        room.addChild(nt);

        // Unread message indicator (red !)
        if (unread?.has(agent.id)) {
          const bangBg = new Graphics();
          const bangX = ax + ntW / 2 + 2;
          bangBg.circle(bangX, nameY + 6, 6).fill(0xff3333);
          bangBg.circle(bangX, nameY + 6, 6).stroke({ width: 1, color: 0xff0000, alpha: 0.6 });
          room.addChild(bangBg);
          const bangTxt = new Text({
            text: "!",
            style: new TextStyle({ fontSize: 8, fill: 0xffffff, fontWeight: "bold", fontFamily: "monospace" }),
          });
          bangTxt.anchor.set(0.5, 0.5);
          bangTxt.position.set(bangX, nameY + 6);
          room.addChild(bangTxt);
        }

        // Role badge (below name, above character)
        const rt = new Text({
          text: pickLocale(
            activeLocale,
            LOCALE_TEXT.role[agent.role as keyof typeof LOCALE_TEXT.role] || {
              ko: agent.role,
              en: agent.role,
              ja: agent.role,
              zh: agent.role,
            },
          ),
          style: new TextStyle({ fontSize: 6, fill: 0xffffff, fontFamily: "system-ui, sans-serif" }),
        });
        rt.anchor.set(0.5, 0.5);
        const rtW = rt.width + 5;
        const rtBg = new Graphics();
        rtBg.roundRect(ax - rtW / 2, nameY + 13, rtW, 9, 2).fill({ color: theme.accent, alpha: 0.7 });
        room.addChild(rtBg);
        rt.position.set(ax, nameY + 17.5);
        room.addChild(rt);

        // ── Chair (behind character) ──
        drawChair(room, ax, charFeetY - TARGET_CHAR_H * 0.18, theme.accent);

        // Break agents: desk+chair stay, character goes to break room
        if (isBreak) {
          // Desk (on top of empty chair)
          drawDesk(room, ax - DESK_W / 2, deskY, false);
          const awayTag = new Text({
            text: pickLocale(activeLocale, LOCALE_TEXT.breakRoom),
            style: new TextStyle({ fontSize: 7, fill: 0xe8a849, fontFamily: "system-ui, sans-serif" }),
          });
          awayTag.anchor.set(0.5, 0.5);
          awayTag.position.set(ax, charFeetY - TARGET_CHAR_H / 2);
          room.addChild(awayTag);
        } else {
          // ── Character sprite (drawn BEFORE desk so legs hide behind it) ──
          const spriteNum = spriteMap.get(agent.id) ?? ((hashStr(agent.id) % 12) + 1);
          const charContainer = new Container();
          charContainer.position.set(ax, charFeetY);
          charContainer.eventMode = "static";
          charContainer.cursor = "pointer";
          charContainer.on("pointerdown", () => cbRef.current.onSelectAgent(agent));

          const frames: Texture[] = [];
          for (let f = 1; f <= 3; f++) {
            const key = `${spriteNum}-D-${f}`;
            if (textures[key]) frames.push(textures[key]);
          }

          if (frames.length > 0) {
            const animSprite = new AnimatedSprite(frames);
            animSprite.anchor.set(0.5, 1);
            const scale = TARGET_CHAR_H / animSprite.texture.height;
            animSprite.scale.set(scale);
            animSprite.gotoAndStop(0);
            if (isOffline) { animSprite.alpha = 0.3; animSprite.tint = 0x888899; }
            charContainer.addChild(animSprite);
          } else {
            const fb = new Text({ text: agent.avatar_emoji || "🤖", style: new TextStyle({ fontSize: 24 }) });
            fb.anchor.set(0.5, 1);
            charContainer.addChild(fb);
          }
          room.addChild(charContainer);

          // ── Desk AFTER character (covers legs) ──
          drawDesk(room, ax - DESK_W / 2, deskY, isWorking);

          const particles = new Container();
          room.addChild(particles);
          animItemsRef.current.push({
            sprite: charContainer, status: agent.status,
            baseX: ax, baseY: charContainer.position.y, particles,
          });

          // ── Active task speech bubble (above name tag) ──
          const activeTask = tasks.find(t => t.assigned_agent_id === agent.id && t.status === "in_progress");
          if (activeTask) {
            const txt = activeTask.title.length > 16 ? activeTask.title.slice(0, 16) + "..." : activeTask.title;
            const bt = new Text({
              text: `💬 ${txt}`,
              style: new TextStyle({ fontSize: 6.5, fill: 0x333333, fontFamily: "system-ui, sans-serif", wordWrap: true, wordWrapWidth: 85 }),
            });
            bt.anchor.set(0.5, 1);
            const bw = Math.min(bt.width + 8, 100);
            const bh = bt.height + 6;
            const bubbleTop = nameY - bh - 6;
            const bubbleG = new Graphics();
            bubbleG.roundRect(ax - bw / 2, bubbleTop, bw, bh, 4).fill(0xffffff);
            bubbleG.roundRect(ax - bw / 2, bubbleTop, bw, bh, 4)
              .stroke({ width: 1.2, color: theme.accent, alpha: 0.4 });
            bubbleG.moveTo(ax - 3, bubbleTop + bh).lineTo(ax, bubbleTop + bh + 4).lineTo(ax + 3, bubbleTop + bh).fill(0xffffff);
            room.addChild(bubbleG);
            bt.position.set(ax, bubbleTop + bh - 3);
            room.addChild(bt);
          }

          // Status indicators (next to character)
          if (isOffline) {
            const zzz = new Text({ text: "💤", style: new TextStyle({ fontSize: 12 }) });
            zzz.anchor.set(0.5, 0.5);
            zzz.position.set(ax + 20, charFeetY - TARGET_CHAR_H / 2);
            room.addChild(zzz);
          }
        }

        // Sub-agents (beside the desk)
        const mySubs = subAgents.filter(s => s.parentAgentId === agent.id);
        mySubs.forEach((sub, si) => {
          const sx = ax + 35 + si * 28;
          const sy = deskY;
          const tg = new Graphics();
          tg.roundRect(sx - 10, sy + DESK_H + 2, 20, 10, 1).fill(0x777788);
          room.addChild(tg);
          const miniNum = ((hashStr(agent.id) + si + 1) % 12) + 1;
          const miniKey = `${miniNum}-D-1`;
          if (textures[miniKey]) {
            const ms = new Sprite(textures[miniKey]);
            ms.anchor.set(0.5, 1);
            ms.scale.set(MINI_CHAR_H / ms.texture.height);
            ms.position.set(sx, sy + DESK_H);
            if (sub.status !== "working") ms.alpha = 0.5;
            room.addChild(ms);
          }
          const abBg = new Graphics();
          abBg.roundRect(sx - 10, sy - 6, 20, 10, 2).fill(0xf59e0b);
          room.addChild(abBg);
          const abTxt = new Text({
            text: pickLocale(activeLocale, LOCALE_TEXT.partTime),
            style: new TextStyle({ fontSize: 6, fill: 0x000000, fontWeight: "bold", fontFamily: "system-ui, sans-serif" }),
          });
          abTxt.anchor.set(0.5, 0.5);
          abTxt.position.set(sx, sy - 1);
          room.addChild(abTxt);
        });
      });

      app.stage.addChild(room);
    });

    // ── BREAK ROOM ──
    const breakAgents = agents.filter(a => a.status === 'break');
    breakAnimItemsRef.current = [];
    breakBubblesRef.current = [];

    const breakRoom = new Container();
    const brx = 4, bry = breakRoomY, brw = OFFICE_W - 8, brh = BREAK_ROOM_H;
    breakRoomRectRef.current = { x: brx, y: bry, w: brw, h: brh };

    // Floor
    const brFloor = new Graphics();
    drawTiledFloor(brFloor, brx, bry, brw, brh, BREAK_THEME.floor1, BREAK_THEME.floor2);
    breakRoom.addChild(brFloor);

    // Wall border
    const brBorder = new Graphics();
    brBorder.roundRect(brx, bry, brw, brh, 3)
      .stroke({ width: 2, color: BREAK_THEME.wall });
    brBorder.roundRect(brx - 1, bry - 1, brw + 2, brh + 2, 4)
      .stroke({ width: 1, color: BREAK_THEME.accent, alpha: 0.25 });
    breakRoom.addChild(brBorder);

    // Sign
    const brSignW = 84;
    const brSignBg = new Graphics();
    brSignBg.roundRect(brx + brw / 2 - brSignW / 2, bry - 4, brSignW, 18, 4).fill(BREAK_THEME.accent);
    breakRoom.addChild(brSignBg);
    const brSignTxt = new Text({
      text: pickLocale(activeLocale, LOCALE_TEXT.breakRoom),
      style: new TextStyle({ fontSize: 9, fill: 0xffffff, fontWeight: "bold", fontFamily: "system-ui, sans-serif" }),
    });
    brSignTxt.anchor.set(0.5, 0.5);
    brSignTxt.position.set(brx + brw / 2, bry + 5);
    breakRoom.addChild(brSignTxt);

    // Furniture layout (relative to room left)
    const furnitureBaseX = brx + 16;
    drawCoffeeMachine(breakRoom, furnitureBaseX, bry + 20);
    drawPlant(breakRoom, furnitureBaseX + 30, bry + 38);
    drawSofa(breakRoom, furnitureBaseX + 50, bry + 56, 0x8b4513);
    drawCoffeeTable(breakRoom, furnitureBaseX + 140, bry + 58);

    // Right side furniture (from room right edge)
    const furnitureRightX = brx + brw - 16;
    drawVendingMachine(breakRoom, furnitureRightX - 26, bry + 20);
    drawPlant(breakRoom, furnitureRightX - 36, bry + 38);
    drawSofa(breakRoom, furnitureRightX - 120, bry + 56, 0x6b3a2a);
    drawHighTable(breakRoom, furnitureRightX - 170, bry + 24);

    // Steam particles container (for coffee machine)
    const steamContainer = new Container();
    breakRoom.addChild(steamContainer);
    breakSteamParticlesRef.current = steamContainer;

    // Break agents placement
    breakAgents.forEach((agent, idx) => {
      const spot = BREAK_SPOTS[idx % BREAK_SPOTS.length];
      const seed = hashStr(agent.id);
      const offsetX = ((seed % 7) - 3);
      const offsetY = ((seed % 5) - 2) * 0.6;

      // Resolve x: positive = from room left, negative = from furnitureRightX (brx+brw-16)
      const spotX = spot.x >= 0
        ? brx + spot.x + offsetX
        : (brx + brw - 16) + spot.x + offsetX;
      const spotY = bry + spot.y + offsetY;

      agentPosRef.current.set(agent.id, { x: spotX, y: spotY });

      // Character sprite
      const spriteNum = spriteMap.get(agent.id) ?? ((seed % 12) + 1);
      const charContainer = new Container();
      charContainer.position.set(spotX, spotY);
      charContainer.eventMode = "static";
      charContainer.cursor = "pointer";
      charContainer.on("pointerdown", () => cbRef.current.onSelectAgent(agent));

      const dirKey = `${spriteNum}-${spot.dir}-1`;
      const fallbackKey = `${spriteNum}-D-1`;
      const tex = textures[dirKey] || textures[fallbackKey];

      if (tex) {
        const sp = new Sprite(tex);
        sp.anchor.set(0.5, 1);
        const scale = (TARGET_CHAR_H * 0.85) / sp.texture.height;
        sp.scale.set(scale);
        charContainer.addChild(sp);
      } else {
        const fb = new Text({ text: agent.avatar_emoji || "🤖", style: new TextStyle({ fontSize: 20 }) });
        fb.anchor.set(0.5, 1);
        charContainer.addChild(fb);
      }
      breakRoom.addChild(charContainer);

      breakAnimItemsRef.current.push({
        sprite: charContainer,
        baseX: spotX,
        baseY: spotY,
      });

      // Coffee emoji next to character
      const coffeeEmoji = new Text({ text: "☕", style: new TextStyle({ fontSize: 10 }) });
      coffeeEmoji.anchor.set(0.5, 0.5);
      coffeeEmoji.position.set(spotX + 14, spotY - 10);
      breakRoom.addChild(coffeeEmoji);

      // Small name tag
      const nameTag = new Text({
        text: activeLocale === "ko" ? (agent.name_ko || agent.name) : agent.name,
        style: new TextStyle({ fontSize: 6, fill: 0xffffff, fontFamily: "system-ui, sans-serif" }),
      });
      nameTag.anchor.set(0.5, 0);
      const ntW = nameTag.width + 4;
      const ntBg = new Graphics();
      ntBg.roundRect(spotX - ntW / 2, spotY + 2, ntW, 9, 2).fill({ color: 0x000000, alpha: 0.4 });
      breakRoom.addChild(ntBg);
      nameTag.position.set(spotX, spotY + 3);
      breakRoom.addChild(nameTag);
    });

    // Chat bubbles (1-2 at a time, rotating)
    if (breakAgents.length > 0) {
      const phase = Math.floor(Date.now() / 4000);
      const speakerCount = Math.min(2, breakAgents.length);
      for (let si = 0; si < speakerCount; si++) {
        const speakerIdx = (phase + si) % breakAgents.length;
        const agent = breakAgents[speakerIdx];
        const spot = BREAK_SPOTS[speakerIdx % BREAK_SPOTS.length];
        const seed = hashStr(agent.id);
        const spotX = spot.x >= 0
          ? brx + spot.x + ((seed % 7) - 3)
          : (brx + brw - 16) + spot.x + ((seed % 7) - 3);
        const spotY = bry + spot.y + ((seed % 5) - 2) * 0.6;

        const chatPool = BREAK_CHAT_MESSAGES[activeLocale] || BREAK_CHAT_MESSAGES.ko;
        const msg = chatPool[(seed + phase) % chatPool.length];
        const bubbleText = new Text({
          text: msg,
          style: new TextStyle({ fontSize: 7, fill: 0x333333, fontFamily: "system-ui, sans-serif" }),
        });
        bubbleText.anchor.set(0.5, 1);
        const bw = bubbleText.width + 10;
        const bh = bubbleText.height + 6;
        const bubbleTop = spotY - TARGET_CHAR_H * 0.85 - bh - 4;

        const bubbleG = new Graphics();
        bubbleG.roundRect(spotX - bw / 2, bubbleTop, bw, bh, 4).fill(0xfff8e8);
        bubbleG.roundRect(spotX - bw / 2, bubbleTop, bw, bh, 4)
          .stroke({ width: 1.2, color: BREAK_THEME.accent, alpha: 0.5 });
        // Tail
        bubbleG.moveTo(spotX - 3, bubbleTop + bh).lineTo(spotX, bubbleTop + bh + 4).lineTo(spotX + 3, bubbleTop + bh).fill(0xfff8e8);
        breakRoom.addChild(bubbleG);
        bubbleText.position.set(spotX, bubbleTop + bh - 3);
        breakRoom.addChild(bubbleText);

        // Store for alpha animation
        const bubbleContainer = new Container();
        bubbleContainer.addChild(bubbleG);
        // Re-parent text into container for animation
        breakRoom.removeChild(bubbleG);
        breakRoom.removeChild(bubbleText);
        bubbleContainer.addChild(bubbleG);
        bubbleContainer.addChild(bubbleText);
        breakRoom.addChild(bubbleContainer);
        breakBubblesRef.current.push(bubbleContainer);
      }
    }

    app.stage.addChild(breakRoom);

    // ── DELIVERY LAYER ──
    const dlLayer = new Container();
    app.stage.addChild(dlLayer);
    deliveryLayerRef.current = dlLayer;

    // ── ROOM HIGHLIGHT (drawn in ticker) ──
    const hl = new Graphics();
    app.stage.addChild(hl);
    highlightRef.current = hl;

    // ── CEO CHARACTER (always on top, moveable) ──
    const ceoChar = new Container();
    if (textures["ceo"]) {
      const sp = new Sprite(textures["ceo"]);
      sp.anchor.set(0.5, 0.5);
      const s = CEO_SIZE / Math.max(sp.texture.width, sp.texture.height);
      sp.scale.set(s);
      ceoChar.addChild(sp);
    } else {
      const fb = new Graphics();
      fb.circle(0, 0, 18).fill(0xff4d4d);
      ceoChar.addChild(fb);
    }

    // Crown above lobster
    const crown = new Text({ text: "👑", style: new TextStyle({ fontSize: 14 }) });
    crown.anchor.set(0.5, 1);
    crown.position.set(0, -CEO_SIZE / 2 + 2);
    ceoChar.addChild(crown);
    crownRef.current = crown;

    // CEO name badge
    const cbg = new Graphics();
    cbg.roundRect(-16, CEO_SIZE / 2 + 1, 32, 11, 3).fill({ color: 0xd4a017, alpha: 0.85 });
    ceoChar.addChild(cbg);
    const cName = new Text({
      text: "CEO",
      style: new TextStyle({ fontSize: 7, fill: 0x000000, fontWeight: "bold", fontFamily: "monospace" }),
    });
    cName.anchor.set(0.5, 0.5);
    cName.position.set(0, CEO_SIZE / 2 + 6.5);
    ceoChar.addChild(cName);

    ceoChar.position.set(ceoPosRef.current.x, ceoPosRef.current.y);
    app.stage.addChild(ceoChar);
    ceoSpriteRef.current = ceoChar;

    // ── Detect new task assignments → delivery animation ──
    const currentAssign = new Set(
      tasks.filter(t => t.assigned_agent_id && t.status === "in_progress").map(t => t.id)
    );
    const newAssigns = [...currentAssign].filter(id => !prevAssignRef.current.has(id));
    prevAssignRef.current = currentAssign;

    if (dlLayer) {
      for (const tid of newAssigns) {
        const task = tasks.find(t => t.id === tid);
        if (!task?.assigned_agent_id) continue;
        const target = agentPosRef.current.get(task.assigned_agent_id);
        if (!target) continue;

        const dc = new Container();
        const docEmoji = new Text({ text: "📋", style: new TextStyle({ fontSize: 16 }) });
        docEmoji.anchor.set(0.5, 0.5);
        dc.addChild(docEmoji);
        dc.position.set(ceoPosRef.current.x, ceoPosRef.current.y);
        dlLayer.addChild(dc);

        deliveriesRef.current.push({
          sprite: dc,
          fromX: ceoPosRef.current.x,
          fromY: ceoPosRef.current.y,
          toX: target.x,
          toY: target.y + DESK_H,
          progress: 0,
        });
      }
    }
  }, []);

  /* ── INIT PIXI APP (runs once on mount) ── */
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    destroyedRef.current = false;

    async function init() {
      if (!el) return;
      TextureStyle.defaultOptions.scaleMode = "nearest";

      // Measure container for responsive width
      officeWRef.current = Math.max(MIN_OFFICE_W, el.clientWidth);

      const app = new Application();
      await app.init({
        width: officeWRef.current,
        height: 600,
        backgroundAlpha: 0,
        antialias: false,
        resolution: Math.min(window.devicePixelRatio || 1, 2),
        autoDensity: true,
      });

      if (destroyedRef.current) { app.destroy(); return; }
      appRef.current = app;
      const canvas = app.canvas as HTMLCanvasElement;
      canvas.style.imageRendering = "pixelated";
      el.innerHTML = "";
      el.appendChild(canvas);

      // Load all textures once
      const textures: Record<string, Texture> = {};
      const loads: Promise<void>[] = [];
      for (let i = 1; i <= 12; i++) {
        for (const f of [1, 2, 3]) {
          const key = `${i}-D-${f}`;
          loads.push(Assets.load<Texture>(`/sprites/${key}.png`).then(t => { textures[key] = t; }).catch(() => {}));
        }
        for (const dir of ['L', 'R']) {
          const key = `${i}-${dir}-1`;
          loads.push(Assets.load<Texture>(`/sprites/${key}.png`).then(t => { textures[key] = t; }).catch(() => {}));
        }
      }
      loads.push(Assets.load<Texture>("/sprites/ceo-lobster.png").then(t => { textures["ceo"] = t; }).catch(() => {}));
      await Promise.all(loads);
      if (destroyedRef.current) { app.destroy(); return; }
      texturesRef.current = textures;

      // Initial scene
      buildScene();
      initDoneRef.current = true;

      // ── ANIMATION TICKER ──
      app.ticker.add(() => {
        if (destroyedRef.current) return;
        const tick = ++tickRef.current;
        const keys = keysRef.current;
        const ceo = ceoSpriteRef.current;

        // CEO movement
        if (ceo) {
          let dx = 0, dy = 0;
          if (keys["ArrowLeft"] || keys["KeyA"]) dx -= CEO_SPEED;
          if (keys["ArrowRight"] || keys["KeyD"]) dx += CEO_SPEED;
          if (keys["ArrowUp"] || keys["KeyW"]) dy -= CEO_SPEED;
          if (keys["ArrowDown"] || keys["KeyS"]) dy += CEO_SPEED;
          if (dx || dy) {
            ceoPosRef.current.x = Math.max(28, Math.min(officeWRef.current - 28, ceoPosRef.current.x + dx));
            ceoPosRef.current.y = Math.max(18, Math.min(totalHRef.current - 28, ceoPosRef.current.y + dy));
            ceo.position.set(ceoPosRef.current.x, ceoPosRef.current.y);
          }

          // Crown bob
          const crown = crownRef.current;
          if (crown) {
            crown.position.y = -CEO_SIZE / 2 + 2 + Math.sin(tick * 0.06) * 2;
            crown.rotation = Math.sin(tick * 0.03) * 0.06;
          }
        }

        // Room highlight when CEO is inside
        const hl = highlightRef.current;
        if (hl) {
          hl.clear();
          const cx = ceoPosRef.current.x, cy = ceoPosRef.current.y;
          let highlighted = false;
          for (const r of roomRectsRef.current) {
            if (cx >= r.x && cx <= r.x + r.w && cy >= r.y - 10 && cy <= r.y + r.h) {
              const theme = DEPT_THEME[r.dept.id] || DEPT_THEME.dev;
              hl.roundRect(r.x - 2, r.y - 2, r.w + 4, r.h + 4, 5)
                .stroke({ width: 3, color: theme.accent, alpha: 0.5 + Math.sin(tick * 0.08) * 0.2 });
              highlighted = true;
              break;
            }
          }
          // Break room highlight
          if (!highlighted) {
            const br = breakRoomRectRef.current;
            if (br && cx >= br.x && cx <= br.x + br.w && cy >= br.y - 10 && cy <= br.y + br.h) {
              hl.roundRect(br.x - 2, br.y - 2, br.w + 4, br.h + 4, 5)
                .stroke({ width: 3, color: BREAK_THEME.accent, alpha: 0.5 + Math.sin(tick * 0.08) * 0.2 });
            }
          }
        }

        // Agent animations
        for (const { sprite, status, baseX, baseY, particles } of animItemsRef.current) {
          // Characters stay seated (no bobbing)
          sprite.position.x = baseX;
          sprite.position.y = baseY;

          if (status === "working") {
            if (tick % 10 === 0) {
              const p = new Graphics();
              const colors = [0x55aaff, 0x55ff88, 0xffaa33, 0xff5577, 0xaa77ff];
              p.star(0, 0, 4, 2, 1, 0).fill(colors[Math.floor(Math.random() * colors.length)]);
              p.position.set(baseX + (Math.random() - 0.5) * 24, baseY - 16 - Math.random() * 8);
              (p as any)._vy = -0.4 - Math.random() * 0.3;
              (p as any)._life = 0;
              particles.addChild(p);
            }
            for (let i = particles.children.length - 1; i >= 0; i--) {
              const p = particles.children[i] as any;
              p._life++;
              p.position.y += p._vy ?? -0.4;
              p.position.x += Math.sin(p._life * 0.2) * 0.2;
              p.alpha = Math.max(0, 1 - p._life * 0.03);
              p.scale.set(Math.max(0.1, 1 - p._life * 0.02));
              if (p._life > 35) { particles.removeChild(p); p.destroy(); }
            }
          }
        }

        // Break room agent sway animation
        for (const { sprite, baseX, baseY } of breakAnimItemsRef.current) {
          const seed = hashStr((sprite as any)._name || `${baseX}`);
          sprite.position.x = baseX + Math.sin(tick * 0.02 + seed) * 1.5;
          sprite.position.y = baseY + Math.sin(tick * 0.03) * 0.8;
        }

        // Coffee steam particles
        const steamC = breakSteamParticlesRef.current;
        if (steamC) {
          if (tick % 20 === 0) {
            const p = new Graphics();
            p.circle(0, 0, 1.5 + Math.random()).fill({ color: 0xffffff, alpha: 0.5 });
            const br = breakRoomRectRef.current;
            if (br) {
              p.position.set(br.x + 26, br.y + 18);
              (p as any)._vy = -0.3 - Math.random() * 0.2;
              (p as any)._life = 0;
              steamC.addChild(p);
            }
          }
          for (let i = steamC.children.length - 1; i >= 0; i--) {
            const p = steamC.children[i] as any;
            p._life++;
            p.position.y += p._vy ?? -0.3;
            p.position.x += Math.sin(p._life * 0.15) * 0.3;
            p.alpha = Math.max(0, 0.5 - p._life * 0.016);
            if (p._life > 30) { steamC.removeChild(p); p.destroy(); }
          }
        }

        // Break room chat bubble alpha pulsing
        for (const bubble of breakBubblesRef.current) {
          const phase = tick * 0.05;
          bubble.alpha = 0.7 + Math.sin(phase) * 0.3;
        }

        // Delivery animations
        const deliveries = deliveriesRef.current;
        const now = Date.now();
        for (let i = deliveries.length - 1; i >= 0; i--) {
          const d = deliveries[i];
          if (d.holdAtSeat && d.arrived) {
            const idleBounce = Math.sin((tick + i * 13) * 0.045) * 1.1;
            d.sprite.position.set(d.toX, d.toY - idleBounce);
            d.sprite.alpha = 1;
            if (d.holdUntil && now >= d.holdUntil) {
              d.sprite.parent?.removeChild(d.sprite);
              d.sprite.destroy({ children: true });
              deliveries.splice(i, 1);
            }
            continue;
          }

          d.progress += d.speed ?? DELIVERY_SPEED;
          if (d.progress >= 1) {
            if (d.holdAtSeat) {
              d.arrived = true;
              d.progress = 1;
              d.sprite.position.set(d.toX, d.toY);
              d.sprite.alpha = 1;
              continue;
            }
            d.sprite.parent?.removeChild(d.sprite);
            d.sprite.destroy({ children: true });
            deliveries.splice(i, 1);
          } else if (d.type === "walk") {
            // Walking character animation — smooth linear walk with bounce
            const t = d.progress;
            const ease = t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
            d.sprite.position.x = d.fromX + (d.toX - d.fromX) * ease;
            d.sprite.position.y = d.fromY + (d.toY - d.fromY) * ease;
            // Walking bounce (small hop)
            const walkBounce = Math.abs(Math.sin(t * Math.PI * 12)) * 3;
            d.sprite.position.y -= walkBounce;
            // Fade in/out at edges
            if (t < 0.05) d.sprite.alpha = t / 0.05;
            else if (t > 0.9) d.sprite.alpha = (1 - t) / 0.1;
            else d.sprite.alpha = 1;
            // Flip direction: face right when moving right, left when moving left
            d.sprite.scale.x = d.toX > d.fromX ? 1 : -1;
          } else {
            // Thrown document animation (CEO → agent)
            const t = d.progress;
            const ease = t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
            const arc = d.arcHeight ?? -30;
            d.sprite.position.x = d.fromX + (d.toX - d.fromX) * ease;
            d.sprite.position.y = d.fromY + (d.toY - d.fromY) * ease + Math.sin(t * Math.PI) * arc;
            d.sprite.alpha = t > 0.85 ? (1 - t) / 0.15 : 1;
            d.sprite.scale.set(0.8 + Math.sin(t * Math.PI) * 0.3);
          }
        }
      });
    }

    // Keyboard handlers
    const isInputFocused = () => {
      const tag = document.activeElement?.tagName;
      return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || (document.activeElement as HTMLElement)?.isContentEditable;
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (isInputFocused()) return;
      if (["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "KeyW", "KeyA", "KeyS", "KeyD"].includes(e.code)) {
        e.preventDefault();
        keysRef.current[e.code] = true;
      }
      if (e.code === "Enter" || e.code === "Space") {
        const cx = ceoPosRef.current.x, cy = ceoPosRef.current.y;
        for (const r of roomRectsRef.current) {
          if (cx >= r.x && cx <= r.x + r.w && cy >= r.y - 10 && cy <= r.y + r.h) {
            cbRef.current.onSelectDepartment(r.dept);
            break;
          }
        }
      }
    };
    const onKeyUp = (e: KeyboardEvent) => {
      if (isInputFocused()) return;
      keysRef.current[e.code] = false;
    };
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("keyup", onKeyUp);

    init();

    // Resize observer for responsive layout
    const ro = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry || !appRef.current || destroyedRef.current) return;
      const newW = Math.max(MIN_OFFICE_W, Math.floor(entry.contentRect.width));
      if (Math.abs(newW - officeWRef.current) > 10) {
        officeWRef.current = newW;
        buildScene();
      }
    });
    if (el) ro.observe(el);

    return () => {
      destroyedRef.current = true;
      ro.disconnect();
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("keyup", onKeyUp);
      if (appRef.current) {
        appRef.current.destroy(true, { children: true });
        appRef.current = null;
      }
    };
  }, [buildScene]);

  /* ── REBUILD SCENE on data change (no app destroy!) ── */
  useEffect(() => {
    if (initDoneRef.current && appRef.current) {
      buildScene();
    }
  }, [departments, agents, tasks, subAgents, unreadAgentIds, language, buildScene]);

  /* ── CROSS-DEPT DELIVERY ANIMATIONS (walking character) ── */
  useEffect(() => {
    if (!crossDeptDeliveries?.length) return;
    const dlLayer = deliveryLayerRef.current;
    const textures = texturesRef.current;
    if (!dlLayer) return;

    for (const cd of crossDeptDeliveries) {
      if (processedCrossDeptRef.current.has(cd.id)) continue;
      processedCrossDeptRef.current.add(cd.id);

      const fromPos = agentPosRef.current.get(cd.fromAgentId);
      const toPos = agentPosRef.current.get(cd.toAgentId);
      if (!fromPos || !toPos) {
        onCrossDeptDeliveryProcessed?.(cd.id);
        continue;
      }

      const dc = new Container();

      // ── Walking character sprite ──
      const spriteNum = spriteMapRef.current.get(cd.fromAgentId) ?? ((hashStr(cd.fromAgentId) % 12) + 1);
      const frames: Texture[] = [];
      for (let f = 1; f <= 3; f++) {
        const key = `${spriteNum}-D-${f}`;
        if (textures[key]) frames.push(textures[key]);
      }

      if (frames.length > 0) {
        const animSprite = new AnimatedSprite(frames);
        animSprite.anchor.set(0.5, 1);
        const scale = 44 / animSprite.texture.height;
        animSprite.scale.set(scale);
        animSprite.animationSpeed = 0.12;
        animSprite.play();
        animSprite.position.set(0, 0);
        dc.addChild(animSprite);
      } else {
        const fb = new Text({ text: "🧑‍💼", style: new TextStyle({ fontSize: 20 }) });
        fb.anchor.set(0.5, 1);
        dc.addChild(fb);
      }

      // ── Document held above head ──
      const docHolder = new Container();
      const docEmoji = new Text({ text: "📋", style: new TextStyle({ fontSize: 13 }) });
      docEmoji.anchor.set(0.5, 0.5);
      docHolder.addChild(docEmoji);
      docHolder.position.set(0, -50);
      dc.addChild(docHolder);

      // ── "협업" badge below feet ──
      const badge = new Graphics();
      badge.roundRect(-16, 3, 32, 13, 4).fill({ color: 0xf59e0b, alpha: 0.9 });
      badge.roundRect(-16, 3, 32, 13, 4).stroke({ width: 1, color: 0xd97706, alpha: 0.5 });
      dc.addChild(badge);
      const badgeText = new Text({
        text: pickLocale(language, LOCALE_TEXT.collabBadge),
        style: new TextStyle({ fontSize: 7, fill: 0x000000, fontWeight: "bold", fontFamily: "system-ui, sans-serif" }),
      });
      badgeText.anchor.set(0.5, 0.5);
      badgeText.position.set(0, 9.5);
      dc.addChild(badgeText);

      dc.position.set(fromPos.x, fromPos.y);
      dlLayer.addChild(dc);

      deliveriesRef.current.push({
        sprite: dc,
        fromX: fromPos.x,
        fromY: fromPos.y,
        toX: toPos.x,
        toY: toPos.y,
        progress: 0,
        speed: 0.005,
        type: "walk",
      });

      onCrossDeptDeliveryProcessed?.(cd.id);
    }
  }, [crossDeptDeliveries, onCrossDeptDeliveryProcessed, language]);

  /* ── CEO OFFICE CALL ANIMATIONS (leaders gather at 6P table) ── */
  useEffect(() => {
    if (!ceoOfficeCalls?.length) return;
    const dlLayer = deliveryLayerRef.current;
    const textures = texturesRef.current;
    if (!dlLayer) return;

    const pickLine = (call: CeoOfficeCall) => {
      const provided = call.line?.trim();
      if (provided) return provided;
      const pool = call.phase === "review"
        ? pickLocale(language, LOCALE_TEXT.reviewLines)
        : pickLocale(language, LOCALE_TEXT.kickoffLines);
      return pool[hashStr(`${call.fromAgentId}-${call.id}`) % pool.length];
    };

    const renderSpeechBubble = (x: number, y: number, phase: "kickoff" | "review", line: string) => {
      const bubble = new Container();
      const bubbleText = new Text({
        text: line,
        style: new TextStyle({
          fontSize: 7,
          fill: 0x2b2b2b,
          fontFamily: "system-ui, sans-serif",
          wordWrap: true,
          wordWrapWidth: 120,
          breakWords: true,
        }),
      });
      bubbleText.anchor.set(0.5, 1);
      const bw = Math.min(bubbleText.width + 12, 122);
      const bh = bubbleText.height + 8;
      const by = -62;
      const bubbleG = new Graphics();
      bubbleG.roundRect(-bw / 2, by - bh, bw, bh, 4).fill(0xfff8e8);
      bubbleG.roundRect(-bw / 2, by - bh, bw, bh, 4).stroke({
        width: 1,
        color: phase === "review" ? 0x34d399 : 0xf59e0b,
        alpha: 0.6,
      });
      bubbleG.moveTo(-3, by).lineTo(0, by + 4).lineTo(3, by).fill(0xfff8e8);
      bubble.addChild(bubbleG);
      bubbleText.position.set(0, by - 4);
      bubble.addChild(bubbleText);

      bubble.position.set(x, y - 6);
      dlLayer.addChild(bubble);

      setTimeout(() => {
        bubble.destroy({ children: true });
      }, 2800);
    };

    for (const call of ceoOfficeCalls) {
      if (processedCeoOfficeRef.current.has(call.id)) continue;
      processedCeoOfficeRef.current.add(call.id);

      const seats = ceoMeetingSeatsRef.current;
      const seat = seats.length > 0 ? seats[call.seatIndex % seats.length] : null;
      if (!seat) {
        onCeoOfficeCallProcessed?.(call.id);
        continue;
      }

      if (call.action === "speak") {
        const line = pickLine(call);
        renderSpeechBubble(seat.x, seat.y, call.phase, line);
        onCeoOfficeCallProcessed?.(call.id);
        continue;
      }

      const fromPos = agentPosRef.current.get(call.fromAgentId);
      if (!fromPos) {
        onCeoOfficeCallProcessed?.(call.id);
        continue;
      }

      const dc = new Container();
      const spriteNum = spriteMapRef.current.get(call.fromAgentId) ?? ((hashStr(call.fromAgentId) % 12) + 1);
      const frames: Texture[] = [];
      for (let f = 1; f <= 3; f++) {
        const key = `${spriteNum}-D-${f}`;
        if (textures[key]) frames.push(textures[key]);
      }

      if (frames.length > 0) {
        const animSprite = new AnimatedSprite(frames);
        animSprite.anchor.set(0.5, 1);
        const scale = 44 / animSprite.texture.height;
        animSprite.scale.set(scale);
        animSprite.animationSpeed = 0.12;
        animSprite.play();
        dc.addChild(animSprite);
      } else {
        const fb = new Text({ text: "🧑‍💼", style: new TextStyle({ fontSize: 20 }) });
        fb.anchor.set(0.5, 1);
        dc.addChild(fb);
      }

      const badge = new Graphics();
      const badgeColor = call.phase === "review" ? 0x34d399 : 0xf59e0b;
      badge.roundRect(-24, 4, 48, 13, 4).fill({ color: badgeColor, alpha: 0.9 });
      badge.roundRect(-24, 4, 48, 13, 4).stroke({ width: 1, color: 0x111111, alpha: 0.35 });
      dc.addChild(badge);
      const badgeText = new Text({
        text: call.phase === "review"
          ? pickLocale(language, LOCALE_TEXT.meetingBadgeReview)
          : pickLocale(language, LOCALE_TEXT.meetingBadgeKickoff),
        style: new TextStyle({ fontSize: 7, fill: 0x111111, fontWeight: "bold", fontFamily: "system-ui, sans-serif" }),
      });
      badgeText.anchor.set(0.5, 0.5);
      badgeText.position.set(0, 10.5);
      dc.addChild(badgeText);

      dc.position.set(fromPos.x, fromPos.y);
      dlLayer.addChild(dc);

      for (let i = deliveriesRef.current.length - 1; i >= 0; i--) {
        const d = deliveriesRef.current[i];
        if (d.agentId !== call.fromAgentId) continue;
        d.sprite.parent?.removeChild(d.sprite);
        d.sprite.destroy({ children: true });
        deliveriesRef.current.splice(i, 1);
      }

      deliveriesRef.current.push({
        sprite: dc,
        fromX: fromPos.x,
        fromY: fromPos.y,
        toX: seat.x,
        toY: seat.y,
        progress: 0,
        speed: 0.0048,
        type: "walk",
        agentId: call.fromAgentId,
        holdAtSeat: true,
        holdUntil: Date.now() + 95_000,
      });

      onCeoOfficeCallProcessed?.(call.id);
    }
  }, [ceoOfficeCalls, onCeoOfficeCallProcessed, language]);

  // ── CLI Usage Gauges ──
  const [cliStatus, setCliStatus] = useState<CliStatusMap | null>(null);
  const [cliUsage, setCliUsage] = useState<Record<string, CliUsageEntry> | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const doneCountRef = useRef(0);

  // Load cached data from SQLite on mount (instant)
  useEffect(() => {
    getCliStatus().then(setCliStatus).catch(() => {});
    getCliUsage().then((r) => { if (r.ok) setCliUsage(r.usage); }).catch(() => {});
  }, []);

  // Auto-refresh when a task completes (done count increases)
  useEffect(() => {
    const doneCount = tasks.filter((t) => t.status === "done").length;
    if (doneCountRef.current > 0 && doneCount > doneCountRef.current) {
      // A new task just completed — refresh usage
      refreshCliUsage().then((r) => { if (r.ok) setCliUsage(r.usage); }).catch(() => {});
    }
    doneCountRef.current = doneCount;
  }, [tasks]);

  const handleRefreshUsage = useCallback(() => {
    if (refreshing) return;
    setRefreshing(true);
    refreshCliUsage()
      .then((r) => { if (r.ok) setCliUsage(r.usage); })
      .catch(() => {})
      .finally(() => setRefreshing(false));
  }, [refreshing]);

  const ClaudeLogo = () => (
    <svg width="18" height="18" viewBox="0 0 400 400" fill="none">
      <path fill="#D97757" d="m124.011 241.251 49.164-27.585.826-2.396-.826-1.333h-2.396l-8.217-.506-28.09-.759-24.363-1.012-23.603-1.266-5.938-1.265L75 197.79l.574-3.661 4.994-3.358 7.153.625 15.808 1.079 23.722 1.637 17.208 1.012 25.493 2.649h4.049l.574-1.637-1.384-1.012-1.079-1.012-24.548-16.635-26.573-17.58-13.919-10.123-7.524-5.129-3.796-4.808-1.637-10.494 6.833-7.525 9.178.624 2.345.625 9.296 7.153 19.858 15.37 25.931 19.098 3.796 3.155 1.519-1.08.185-.759-1.704-2.851-14.104-25.493-15.049-25.931-6.698-10.747-1.772-6.445c-.624-2.649-1.08-4.876-1.08-7.592l7.778-10.561L144.729 75l10.376 1.383 4.37 3.797 6.445 14.745 10.443 23.215 16.197 31.566 4.741 9.364 2.53 8.672.945 2.649h1.637v-1.519l1.332-17.782 2.464-21.832 2.395-28.091.827-7.912 3.914-9.482 7.778-5.129 6.074 2.902 4.994 7.153-.692 4.623-2.969 19.301-5.821 30.234-3.796 20.245h2.21l2.531-2.53 10.241-13.599 17.208-21.511 7.593-8.537 8.857-9.431 5.686-4.488h10.747l7.912 11.76-3.543 12.147-11.067 14.037-9.178 11.895-13.16 17.714-8.216 14.172.759 1.131 1.957-.186 29.727-6.327 16.062-2.901 19.166-3.29 8.672 4.049.944 4.116-3.408 8.419-20.498 5.062-24.042 4.808-35.801 8.469-.439.321.506.624 16.13 1.519 6.9.371h16.888l31.448 2.345 8.217 5.433 4.926 6.647-.827 5.061-12.653 6.445-17.074-4.049-39.85-9.482-13.666-3.408h-1.889v1.131l11.388 11.135 20.87 18.845 26.133 24.295 1.333 6.006-3.357 4.741-3.543-.506-22.962-17.277-8.858-7.777-20.06-16.888H238.5v1.771l4.623 6.765 24.413 36.696 1.265 11.253-1.771 3.661-6.327 2.21-6.951-1.265-14.29-20.06-14.745-22.591-11.895-20.246-1.451.827-7.018 75.601-3.29 3.863-7.592 2.902-6.327-4.808-3.357-7.778 3.357-15.37 4.049-20.06 3.29-15.943 2.969-19.807 1.772-6.58-.118-.439-1.451.186-14.931 20.498-22.709 30.689-17.968 19.234-4.302 1.704-7.458-3.864.692-6.9 4.167-6.141 24.869-31.634 14.999-19.605 9.684-11.32-.068-1.637h-.573l-66.052 42.887-11.759 1.519-5.062-4.741.625-7.778 2.395-2.531 19.858-13.665-.068.067z"/>
    </svg>
  );

  const ChatGPTLogo = () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <path d="M22.282 9.821a5.985 5.985 0 00-.516-4.91 6.046 6.046 0 00-6.51-2.9A6.065 6.065 0 0011.708.413a6.12 6.12 0 00-5.834 4.27 5.984 5.984 0 00-3.996 2.9 6.043 6.043 0 00.743 7.097 5.98 5.98 0 00.51 4.911 6.051 6.051 0 006.515 2.9A5.985 5.985 0 0013.192 24a6.116 6.116 0 005.84-4.27 5.99 5.99 0 003.997-2.9 6.056 6.056 0 00-.747-7.01zM13.192 22.784a4.474 4.474 0 01-2.876-1.04l.141-.081 4.779-2.758a.795.795 0 00.392-.681v-6.737l2.02 1.168a.071.071 0 01.038.052v5.583a4.504 4.504 0 01-4.494 4.494zM3.658 18.607a4.47 4.47 0 01-.535-3.014l.142.085 4.783 2.759a.77.77 0 00.78 0l5.843-3.369v2.332a.08.08 0 01-.033.062L9.74 20.236a4.508 4.508 0 01-6.083-1.63zM2.328 7.847A4.477 4.477 0 014.68 5.879l-.002.159v5.52a.78.78 0 00.391.676l5.84 3.37-2.02 1.166a.08.08 0 01-.073.007L3.917 13.98a4.506 4.506 0 01-1.589-6.132zM19.835 11.94l-5.844-3.37 2.02-1.166a.08.08 0 01.073-.007l4.898 2.794a4.494 4.494 0 01-.69 8.109v-5.68a.79.79 0 00-.457-.68zm2.01-3.023l-.141-.085-4.774-2.782a.776.776 0 00-.785 0L10.302 9.42V7.088a.08.08 0 01.033-.062l4.898-2.824a4.497 4.497 0 016.612 4.66v.054zM9.076 12.59l-2.02-1.164a.08.08 0 01-.038-.057V5.79A4.498 4.498 0 0114.392 3.2l-.141.08-4.778 2.758a.795.795 0 00-.392.681l-.005 5.87zm1.098-2.358L12 9.019l1.826 1.054v2.109L12 13.235l-1.826-1.054v-2.108z" fill="#10A37F"/>
    </svg>
  );

  const GeminiLogo = () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <path d="M12 0C12 6.627 6.627 12 0 12c6.627 0 12 5.373 12 12 0-6.627 5.373-12 12-12-6.627 0-12-5.373-12-12z" fill="url(#gemini_grad)"/>
      <defs>
        <linearGradient id="gemini_grad" x1="0" y1="0" x2="24" y2="24" gradientUnits="userSpaceOnUse">
          <stop stopColor="#4285F4"/>
          <stop offset="1" stopColor="#886FBF"/>
        </linearGradient>
      </defs>
    </svg>
  );

  const CLI_DISPLAY: Array<{ key: string; name: string; icon: React.ReactNode; color: string; bgColor: string }> = [
    { key: "claude", name: "Claude", icon: <ClaudeLogo />, color: "text-violet-300", bgColor: "bg-violet-500/15 border-violet-400/30" },
    { key: "codex", name: "Codex", icon: <ChatGPTLogo />, color: "text-emerald-300", bgColor: "bg-emerald-500/15 border-emerald-400/30" },
    { key: "gemini", name: "Gemini", icon: <GeminiLogo />, color: "text-blue-300", bgColor: "bg-blue-500/15 border-blue-400/30" },
    { key: "copilot", name: "Copilot", icon: "\uD83D\uDE80", color: "text-amber-300", bgColor: "bg-amber-500/15 border-amber-400/30" },
    { key: "antigravity", name: "Antigravity", icon: "\uD83C\uDF0C", color: "text-pink-300", bgColor: "bg-pink-500/15 border-pink-400/30" },
  ];

  const connectedClis = CLI_DISPLAY.filter((c) => {
    const s = cliStatus?.[c.key as keyof CliStatusMap];
    return s?.installed && s?.authenticated;
  });

  return (
    <div className="w-full overflow-auto" style={{ minHeight: "100%" }}>
      <div
        ref={containerRef}
        className="mx-auto"
        style={{ maxWidth: "100%", lineHeight: 0, outline: "none" }}
        tabIndex={0}
      />

      {/* CLI Usage Gauges */}
      {connectedClis.length > 0 && (
        <div className="mt-4 px-2">
          <div className="rounded-2xl border border-slate-700/60 bg-slate-900/80 p-4 backdrop-blur-sm">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                <span className="flex h-6 w-6 items-center justify-center rounded-lg bg-cyan-500/20">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" className="text-cyan-400">
                    <path d="M12 2a10 10 0 1 0 10 10" />
                    <path d="M12 2a10 10 0 0 1 10 10" strokeOpacity="0.3" />
                    <path d="M12 6v6l4 2" />
                  </svg>
                </span>
                {t(LOCALE_TEXT.cliUsageTitle)}
              </h3>
              <div className="flex items-center gap-2">
                <span className="rounded-full bg-slate-800 px-2 py-0.5 text-[10px] text-slate-400">
                  {connectedClis.length} {t(LOCALE_TEXT.cliConnected)}
                </span>
                <button
                  onClick={handleRefreshUsage}
                  disabled={refreshing}
                  className="flex h-6 w-6 items-center justify-center rounded-lg bg-slate-800 text-slate-400 transition-colors hover:bg-slate-700 hover:text-slate-200 disabled:opacity-50"
                  title={t(LOCALE_TEXT.cliRefreshTitle)}
                >
                  <svg
                    width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
                    className={refreshing ? "animate-spin" : ""}
                  >
                    <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                    <polyline points="21 3 21 9 15 9" />
                  </svg>
                </button>
              </div>
            </div>
            <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
              {connectedClis.map((cli) => {
                const usage = cliUsage?.[cli.key];
                return (
                  <div
                    key={cli.key}
                    className={`group rounded-xl border ${cli.bgColor} p-3 transition-all duration-300 hover:-translate-y-0.5 hover:shadow-lg`}
                  >
                    <div className="mb-2 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="flex h-[18px] w-[18px] items-center justify-center text-base">{cli.icon}</span>
                        <span className={`text-sm font-semibold ${cli.color}`}>{cli.name}</span>
                      </div>
                    </div>

                    {/* Error / empty states */}
                    {usage?.error === "unauthenticated" && (
                      <p className="text-[11px] text-slate-500 italic">{t(LOCALE_TEXT.cliNotSignedIn)}</p>
                    )}
                    {usage?.error === "not_implemented" && (
                      <p className="text-[11px] text-slate-500 italic">{t(LOCALE_TEXT.cliNoApi)}</p>
                    )}
                    {usage?.error && usage.error !== "unauthenticated" && usage.error !== "not_implemented" && (
                      <p className="text-[11px] text-slate-500 italic">{t(LOCALE_TEXT.cliUnavailable)}</p>
                    )}

                    {/* Loading */}
                    {!usage && (
                      <p className="text-[11px] text-slate-500 italic">{t(LOCALE_TEXT.cliLoading)}</p>
                    )}

                    {/* Window bars */}
                    {usage && !usage.error && usage.windows.length > 0 && (
                      <div className={
                        usage.windows.length > 3
                          ? "grid grid-cols-1 gap-1.5 sm:grid-cols-2"
                          : "flex flex-col gap-1.5"
                      }>
                        {usage.windows.map((w: CliUsageWindow) => {
                          const pct = Math.round(w.utilization * 100);
                          const barColor =
                            pct >= 80
                              ? "bg-red-500"
                              : pct >= 50
                                ? "bg-amber-400"
                                : "bg-emerald-400";
                          return (
                            <div key={w.label}>
                              <div className="mb-0.5 flex items-center justify-between text-[10px]">
                                <span className="text-slate-400">{w.label}</span>
                                <span className="flex items-center gap-1.5">
                                  <span
                                    className={
                                      pct >= 80
                                        ? "font-semibold text-red-400"
                                        : pct >= 50
                                          ? "text-amber-400"
                                          : "text-slate-400"
                                    }
                                  >
                                    {pct}%
                                  </span>
                                  {w.resetsAt && (
                                    <span className="text-slate-500">
                                      {t(LOCALE_TEXT.cliResets)} {formatReset(w.resetsAt, language)}
                                    </span>
                                  )}
                                </span>
                              </div>
                              <div className="h-2 overflow-hidden rounded-full bg-slate-700/60">
                                <div
                                  className={`h-full rounded-full ${barColor} transition-all duration-700`}
                                  style={{ width: `${Math.min(100, pct)}%` }}
                                />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}

                    {/* No windows but no error */}
                    {usage && !usage.error && usage.windows.length === 0 && (
                      <p className="text-[11px] text-slate-500 italic">{t(LOCALE_TEXT.cliNoData)}</p>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
