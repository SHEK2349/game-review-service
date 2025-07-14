# ゲームレビューサービス 基本設計書

**文書バージョン:** 1.0  
**作成日:** 2025年7月14日  
**作成者:** 開発チーム  

## 1. システム概要

### 1.1. システム全体構成

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Mobile App    │    │   Web Admin     │    │  External APIs  │
│  (React Native) │    │    (React)      │    │ (OpenAI, etc.)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                        │                        │
         │ HTTPS/REST API         │ HTTPS/REST API         │ HTTPS
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                        API Gateway                             │
│                       (Node.js/Express)                        │
├─────────────────────────────────────────────────────────────────┤
│                      Business Logic Layer                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│  │    Auth     │ │   Review    │ │     AI      │ │   Content   ││
│  │  Service    │ │  Service    │ │  Service    │ │  Moderation ││
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘│
└─────────────────────────────────────────────────────────────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │     Redis       │    │    AWS S3       │
│ (User/Review    │    │   (Session/     │    │ (Audio Files/   │
│     Data)       │    │    Cache)       │    │    Images)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 1.2. アーキテクチャ設計方針

#### 1.2.1. マイクロサービス的アプローチ
- **サービス分離**: 認証、レビュー、AI分析、コンテンツ管理を独立したサービスとして設計
- **疎結合**: 各サービス間はREST APIで通信
- **独立デプロイ**: 各サービスを独立してデプロイ・スケール可能

#### 1.2.2. レイヤードアーキテクチャ
- **プレゼンテーション層**: React Native (Mobile), React (Admin)
- **API層**: Express.js + TypeScript
- **ビジネスロジック層**: Domain Services
- **データアクセス層**: Prisma ORM
- **データ層**: PostgreSQL, Redis, AWS S3

## 2. システム構成要素

### 2.1. フロントエンド設計

#### 2.1.1. モバイルアプリ (React Native + Expo)

```
apps/mobile/
├── src/
│   ├── components/           # 再利用可能なUIコンポーネント
│   │   ├── common/          # 共通コンポーネント
│   │   ├── review/          # レビュー関連コンポーネント
│   │   └── ui/              # UIライブラリコンポーネント
│   ├── screens/             # 画面コンポーネント
│   │   ├── auth/            # 認証関連画面
│   │   ├── review/          # レビュー関連画面
│   │   └── profile/         # プロフィール関連画面
│   ├── navigation/          # ナビゲーション設定
│   ├── services/            # API通信
│   ├── store/               # 状態管理 (Zustand)
│   ├── hooks/               # カスタムフック
│   ├── utils/               # ユーティリティ関数
│   └── types/               # TypeScript型定義
├── assets/                  # 画像・フォント等
└── app.json                 # Expo設定
```

#### 2.1.2. 管理画面 (React)

```
apps/admin/
├── src/
│   ├── components/          # 管理画面コンポーネント
│   ├── pages/               # 画面コンポーネント
│   │   ├── dashboard/       # ダッシュボード
│   │   ├── users/           # ユーザー管理
│   │   ├── reviews/         # レビュー管理
│   │   └── moderation/      # コンテンツ審査
│   ├── services/            # API通信
│   └── utils/               # ユーティリティ
└── public/                  # 静的ファイル
```

### 2.2. バックエンド設計

#### 2.2.1. API サーバー構成

```
apps/api/
├── src/
│   ├── controllers/         # リクエスト処理
│   │   ├── auth.controller.ts
│   │   ├── review.controller.ts
│   │   ├── user.controller.ts
│   │   └── ai.controller.ts
│   ├── services/            # ビジネスロジック
│   │   ├── auth.service.ts
│   │   ├── review.service.ts
│   │   ├── ai.service.ts
│   │   └── moderation.service.ts
│   ├── models/              # データモデル
│   ├── middleware/          # ミドルウェア
│   │   ├── auth.middleware.ts
│   │   ├── validation.middleware.ts
│   │   └── error.middleware.ts
│   ├── routes/              # ルーティング
│   ├── utils/               # ユーティリティ
│   └── types/               # 型定義
├── prisma/                  # データベーススキーマ
├── tests/                   # テストコード
└── docs/                    # API仕様書
```

### 2.3. 共通パッケージ

```
packages/
├── shared/                  # 共通型定義・ユーティリティ
│   ├── types/               # TypeScript型定義
│   ├── constants/           # 定数
│   └── utils/               # 共通ユーティリティ
└── eslint-config/           # ESLint設定
```

## 3. データベース設計

### 3.1. PostgreSQL スキーマ設計

#### 3.1.1. 主要テーブル

```sql
-- ユーザーテーブル
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    nickname VARCHAR(50) NOT NULL,
    birth_date DATE NOT NULL,
    profile_image_url TEXT,
    is_parental_consent_required BOOLEAN DEFAULT FALSE,
    parental_consent_status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ゲームテーブル
CREATE TABLE games (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    platform VARCHAR(100) NOT NULL,
    genre VARCHAR(100),
    developer VARCHAR(255),
    release_date DATE,
    image_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- レビューテーブル
CREATE TABLE reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    game_id UUID REFERENCES games(id) ON DELETE CASCADE,
    audio_file_url TEXT NOT NULL,
    audio_duration INTEGER NOT NULL, -- 秒数
    transcribed_text TEXT,
    highlight_text TEXT,
    play_time_hours INTEGER,
    status VARCHAR(20) DEFAULT 'pending', -- pending, approved, rejected
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 面白さ成分テーブル
CREATE TABLE review_components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID REFERENCES reviews(id) ON DELETE CASCADE,
    story_score INTEGER CHECK (story_score >= 0 AND story_score <= 10),
    character_score INTEGER CHECK (character_score >= 0 AND character_score <= 10),
    music_score INTEGER CHECK (music_score >= 0 AND music_score <= 10),
    controls_score INTEGER CHECK (controls_score >= 0 AND controls_score <= 10),
    multiplayer_score INTEGER CHECK (multiplayer_score >= 0 AND multiplayer_score <= 10),
    solo_score INTEGER CHECK (solo_score >= 0 AND solo_score <= 10),
    is_ai_generated BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- いいねテーブル
CREATE TABLE likes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    review_id UUID REFERENCES reviews(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, review_id)
);

-- コメントテーブル
CREATE TABLE comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    review_id UUID REFERENCES reviews(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 通報テーブル
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_id UUID REFERENCES users(id) ON DELETE CASCADE,
    review_id UUID REFERENCES reviews(id) ON DELETE CASCADE,
    reason VARCHAR(100) NOT NULL,
    description TEXT,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### 3.1.2. インデックス設計

```sql
-- パフォーマンス向上のためのインデックス
CREATE INDEX idx_reviews_user_id ON reviews(user_id);
CREATE INDEX idx_reviews_game_id ON reviews(game_id);
CREATE INDEX idx_reviews_created_at ON reviews(created_at DESC);
CREATE INDEX idx_reviews_status ON reviews(status);
CREATE INDEX idx_likes_review_id ON likes(review_id);
CREATE INDEX idx_games_title ON games(title);
```

### 3.2. Redis キャッシュ設計

#### 3.2.1. キャッシュ戦略

```typescript
// セッション管理
session:{user_id} -> session_data

// レビューキャッシュ（人気レビュー）
popular_reviews:{page} -> review_list

// ゲーム情報キャッシュ
game:{game_id} -> game_data

// AI分析結果キャッシュ
ai_analysis:{audio_hash} -> analysis_result

// レート制限
rate_limit:{user_id}:{endpoint} -> request_count
```

## 4. API設計

### 4.1. RESTful API 設計原則

#### 4.1.1. エンドポイント命名規則
- **リソースベース**: `/api/v1/reviews`, `/api/v1/users`
- **HTTP動詞**: GET(取得), POST(作成), PUT(更新), DELETE(削除)
- **階層構造**: `/api/v1/users/{userId}/reviews`

#### 4.1.2. 主要エンドポイント

```typescript
// 認証関連
POST   /api/v1/auth/register          // ユーザー登録
POST   /api/v1/auth/login             // ログイン
POST   /api/v1/auth/logout            // ログアウト
POST   /api/v1/auth/refresh           // トークン更新
POST   /api/v1/auth/parental-consent  // 保護者同意

// ユーザー関連
GET    /api/v1/users/me               // 自分の情報取得
PUT    /api/v1/users/me               // 自分の情報更新
GET    /api/v1/users/{id}/reviews     // ユーザーのレビュー一覧

// レビュー関連
POST   /api/v1/reviews                // レビュー作成
GET    /api/v1/reviews                // レビュー一覧取得
GET    /api/v1/reviews/{id}           // レビュー詳細取得
PUT    /api/v1/reviews/{id}           // レビュー更新
DELETE /api/v1/reviews/{id}           // レビュー削除
POST   /api/v1/reviews/{id}/like      // いいね
POST   /api/v1/reviews/{id}/comments  // コメント追加

// AI分析関連
POST   /api/v1/ai/analyze-audio       // 音声分析
POST   /api/v1/ai/generate-components // 成分グラフ生成

// ゲーム関連
GET    /api/v1/games                  // ゲーム検索
GET    /api/v1/games/{id}             // ゲーム詳細
POST   /api/v1/games                  // ゲーム登録

// アップロード関連
POST   /api/v1/upload/audio           // 音声ファイルアップロード
POST   /api/v1/upload/image           // 画像アップロード
```

### 4.2. レスポンス形式統一

#### 4.2.1. 成功レスポンス

```typescript
interface SuccessResponse<T> {
  success: true;
  data: T;
  meta?: {
    total?: number;
    page?: number;
    limit?: number;
  };
}
```

#### 4.2.2. エラーレスポンス

```typescript
interface ErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: any;
  };
}
```

## 5. セキュリティ設計

### 5.1. 認証・認可

#### 5.1.1. JWT トークン設計

```typescript
interface JWTPayload {
  userId: string;
  email: string;
  role: 'user' | 'admin' | 'moderator';
  isParentalConsentRequired: boolean;
  iat: number;
  exp: number;
}
```

#### 5.1.2. 認可フロー

```typescript
// ミドルウェアでの認可チェック
const authMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  // 1. トークン検証
  // 2. ユーザー存在確認
  // 3. 権限チェック
  // 4. 保護者同意確認（必要な場合）
};
```

### 5.2. データ保護

#### 5.2.1. 暗号化戦略
- **通信暗号化**: TLS 1.3
- **データベース暗号化**: PostgreSQL TDE
- **ファイル暗号化**: AWS S3 Server-Side Encryption
- **パスワードハッシュ化**: bcrypt (salt rounds: 12)

#### 5.2.2. 個人情報保護
- **データ最小化**: 必要最小限の情報のみ収集
- **仮名化**: 表示用IDと内部IDの分離
- **自動削除**: 非アクティブユーザーのデータ自動削除

### 5.3. コンテンツ安全性

#### 5.3.1. 多層防御アプローチ

```typescript
// 1. 入力時フィルタリング
const inputFilter = {
  ngWordCheck: (text: string) => boolean,
  profanityDetection: (text: string) => boolean,
  lengthValidation: (text: string, max: number) => boolean
};

// 2. AI審査
const aiModeration = {
  openaiModeration: (text: string) => Promise<ModerationResult>,
  customClassifier: (text: string) => Promise<SafetyScore>
};

// 3. 人間による審査
const humanModeration = {
  flaggedContent: (contentId: string) => Promise<void>,
  approvalWorkflow: (contentId: string) => Promise<ApprovalStatus>
};
```

## 6. パフォーマンス設計

### 6.1. キャッシュ戦略

#### 6.1.1. 多段キャッシュ
- **アプリケーションキャッシュ**: Node.js メモリキャッシュ
- **Redisキャッシュ**: セッション、人気コンテンツ
- **CDNキャッシュ**: 静的ファイル、画像

#### 6.1.2. キャッシュ無効化戦略
- **TTL設定**: データ種別に応じた適切な有効期限
- **イベント駆動**: データ更新時の関連キャッシュ削除
- **段階的無効化**: 影響範囲を最小化

### 6.2. データベース最適化

#### 6.2.1. クエリ最適化
- **インデックス**: 頻繁な検索条件にインデックス作成
- **N+1問題回避**: Prismaのincludeを適切に使用
- **ページネーション**: offset-limitとcursor-basedの使い分け

#### 6.2.2. 読み取り専用レプリカ
- **読み書き分離**: マスター/スレーブ構成
- **負荷分散**: 読み取り処理のスレーブ分散

## 7. モニタリング・ログ設計

### 7.1. ログ設計

#### 7.1.1. ログレベル
- **ERROR**: エラー・例外
- **WARN**: 警告・潜在的問題
- **INFO**: 重要なイベント
- **DEBUG**: デバッグ情報

#### 7.1.2. 構造化ログ

```typescript
interface LogEntry {
  timestamp: string;
  level: 'error' | 'warn' | 'info' | 'debug';
  message: string;
  service: string;
  userId?: string;
  requestId: string;
  metadata?: Record<string, any>;
}
```

### 7.2. メトリクス設計

#### 7.2.1. ビジネスメトリクス
- **ユーザー関連**: MAU, DAU, 継続率
- **コンテンツ関連**: 投稿数、いいね数、コメント数
- **品質関連**: AI分析精度、審査通過率

#### 7.2.2. 技術メトリクス
- **パフォーマンス**: 応答時間、スループット
- **可用性**: 稼働率、エラー率
- **リソース**: CPU、メモリ、ディスク使用率

## 8. デプロイメント設計

### 8.1. 環境構成

#### 8.1.1. 環境分離
- **Development**: 開発者ローカル環境
- **Staging**: 本番同等のテスト環境
- **Production**: 本番環境

#### 8.1.2. インフラ構成

```yaml
# Vercel (フロントエンド)
- Mobile App (Static Export)
- Admin Dashboard
- API Gateway

# PlanetScale (データベース)
- Main Database (Production)
- Staging Database
- Development Database

# AWS S3 (ファイルストレージ)
- Audio Files
- Images
- Static Assets

# Redis Cloud (キャッシュ)
- Session Store
- Application Cache
```

### 8.2. CI/CD パイプライン

#### 8.2.1. ビルドパイプライン

```yaml
# GitHub Actions
name: Build and Deploy
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    - Lint check (ESLint, Prettier)
    - Type check (TypeScript)
    - Unit tests (Jest)
    - Integration tests
    
  build:
    - Build mobile app
    - Build admin dashboard
    - Build API server
    
  deploy:
    - Deploy to staging (develop branch)
    - Deploy to production (main branch)
    - Database migration
    - Health check
```

## 9. 運用設計

### 9.1. 監視・アラート

#### 9.1.1. ヘルスチェック
- **API Health**: `/health` エンドポイント
- **Database Health**: 接続確認、レスポンス時間
- **External Service Health**: OpenAI API、AWS S3

#### 9.1.2. アラート設定
- **Critical**: サービス停止、データベース接続不可
- **Warning**: 応答時間悪化、エラー率上昇
- **Info**: デプロイ完了、スケールイベント

### 9.2. バックアップ・復旧

#### 9.2.1. データバックアップ
- **データベース**: 毎日自動バックアップ (7日保持)
- **ファイル**: S3のバージョニング機能
- **設定**: Infrastructure as Code (Terraform)

#### 9.2.2. 災害復旧計画
- **RTO**: 4時間以内
- **RPO**: 1時間以内
- **復旧手順**: 自動化されたスクリプト

---

**レビュー・承認:**
- アーキテクト: ___________
- 開発リーダー: ___________
- インフラ担当: ___________