# ゲームレビューサービス セキュリティ要件書

**文書バージョン:** 1.0  
**作成日:** 2025年7月14日  
**作成者:** セキュリティチーム  
**承認者:** セキュリティ責任者  

## 1. セキュリティ方針

### 1.1. 基本方針

子供向けSNSサービスとして、最高レベルのセキュリティとプライバシー保護を実現し、安全で健全なコミュニティ環境を提供する。

#### 1.1.1. セキュリティ原則
- **最小権限の原則**: 必要最小限のアクセス権のみ付与
- **多層防御**: 複数のセキュリティ層による防御
- **ゼロトラスト**: すべてのアクセスを検証
- **プライバシー・バイ・デザイン**: 設計段階からプライバシー保護を組み込み

#### 1.1.2. 対象範囲
- フロントエンド（React Native アプリ）
- バックエンド（Node.js API）
- データベース（PostgreSQL、Redis）
- インフラストラクチャ（AWS、Vercel、PlanetScale）
- 外部API連携（OpenAI、Firebase Auth）

## 2. 脅威モデル分析

### 2.1. 資産の分類

#### 2.1.1. 機密資産（Critical）
- **個人情報**: ユーザーの生年月日、メールアドレス
- **音声データ**: ユーザーが投稿した音声ファイル
- **認証情報**: パスワードハッシュ、JWT秘密鍵
- **API キー**: OpenAI API キー、その他外部サービスキー

#### 2.1.2. 重要資産（High）
- **レビューコンテンツ**: テキスト化された音声内容
- **ユーザー行動データ**: いいね、コメント、閲覧履歴
- **アプリケーションソースコード**
- **データベース接続情報**

#### 2.1.3. 通常資産（Medium）
- **ゲーム情報**: タイトル、画像、メタデータ
- **公開レビューデータ**: 承認済みレビュー
- **システムログ**

### 2.2. 脅威の識別

#### 2.2.1. 外部脅威
- **悪意のあるユーザー**: 不適切コンテンツ投稿、なりすまし
- **サイバー攻撃者**: SQLインジェクション、XSS、DDoS攻撃
- **データ窃取**: 個人情報・音声データの不正取得
- **フィッシング攻撃**: 偽サイトでの認証情報窃取

#### 2.2.2. 内部脅威
- **内部者による不正アクセス**: 開発者・運用者による権限濫用
- **設定ミス**: セキュリティ設定の不備
- **開発工程での情報漏洩**: ソースコード、認証情報の露出

#### 2.2.3. 技術的脅威
- **認証・認可の脆弱性**: JWT改ざん、セッションハイジャック
- **入力検証不備**: インジェクション攻撃
- **暗号化の不備**: 通信・保存データの盗聴・改ざん
- **依存関係の脆弱性**: ライブラリ・フレームワークの既知脆弱性

### 2.3. リスク評価マトリックス

| 脅威 | 影響度 | 発生確率 | リスクレベル | 対策優先度 |
|------|--------|----------|--------------|------------|
| 個人情報漏洩 | 高 | 中 | **高** | 1 |
| 音声データ流出 | 高 | 中 | **高** | 1 |
| 不適切コンテンツ拡散 | 高 | 高 | **高** | 1 |
| SQLインジェクション | 高 | 低 | 中 | 2 |
| XSS攻撃 | 中 | 中 | 中 | 2 |
| DDoS攻撃 | 中 | 中 | 中 | 3 |
| 内部者不正アクセス | 高 | 低 | 中 | 2 |

## 3. 認証・認可セキュリティ

### 3.1. ユーザー認証

#### 3.1.1. パスワードポリシー
```typescript
interface PasswordPolicy {
  minLength: 8;
  maxLength: 128;
  requireUppercase: true;
  requireLowercase: true;
  requireNumbers: true;
  requireSpecialChars: false; // 子供の利便性を考慮
  preventCommonPasswords: true;
  preventPersonalInfo: true; // ニックネーム、メールを含む禁止
}

// 実装例
export class PasswordValidator {
  private commonPasswords = new Set([
    'password', '12345678', 'qwerty', ...
  ]);

  validate(password: string, userInfo: UserInfo): ValidationResult {
    if (password.length < 8 || password.length > 128) {
      return { valid: false, error: 'パスワードは8文字以上128文字以下で入力してください' };
    }

    if (!/[A-Z]/.test(password)) {
      return { valid: false, error: '大文字を含めてください' };
    }

    if (!/[a-z]/.test(password)) {
      return { valid: false, error: '小文字を含めてください' };
    }

    if (!/[0-9]/.test(password)) {
      return { valid: false, error: '数字を含めてください' };
    }

    if (this.commonPasswords.has(password.toLowerCase())) {
      return { valid: false, error: 'より安全なパスワードを選択してください' };
    }

    // 個人情報チェック
    if (password.toLowerCase().includes(userInfo.nickname.toLowerCase()) ||
        password.toLowerCase().includes(userInfo.email.split('@')[0].toLowerCase())) {
      return { valid: false, error: 'ニックネームやメールアドレスを含むパスワードは使用できません' };
    }

    return { valid: true };
  }
}
```

#### 3.1.2. 多要素認証（MFA）
```typescript
interface MFAConfig {
  mandatory: false; // 子供の利便性を考慮し任意
  methods: ['sms', 'email']; // TOTP は複雑なため除外
  gracePeriod: 30; // 30日間はMFA無しでログイン可能
}

export class MFAService {
  async sendVerificationCode(userId: string, method: 'sms' | 'email'): Promise<void> {
    const code = this.generateSecureCode(6); // 6桁数字
    const expiryTime = new Date(Date.now() + 5 * 60 * 1000); // 5分

    await this.storeVerificationCode(userId, code, expiryTime);

    if (method === 'sms') {
      await this.smsService.send(user.phoneNumber, `認証コード: ${code}`);
    } else {
      await this.emailService.sendVerificationCode(user.email, code);
    }
  }

  async verifyCode(userId: string, inputCode: string): Promise<boolean> {
    const storedCode = await this.getStoredCode(userId);
    
    if (!storedCode || storedCode.expiryTime < new Date()) {
      return false;
    }

    const isValid = this.constantTimeCompare(inputCode, storedCode.code);
    
    if (isValid) {
      await this.deleteStoredCode(userId);
      await this.recordSuccessfulMFA(userId);
    } else {
      await this.recordFailedMFA(userId);
    }

    return isValid;
  }

  private constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }
}
```

#### 3.1.3. JWT セキュリティ
```typescript
interface JWTConfig {
  algorithm: 'HS256';
  accessTokenExpiry: '15m';
  refreshTokenExpiry: '7d';
  issuer: 'game-review-service';
  audience: 'game-review-users';
}

export class JWTService {
  private readonly secretKey: string;
  private readonly refreshSecretKey: string;

  constructor() {
    this.secretKey = process.env.JWT_SECRET_KEY!;
    this.refreshSecretKey = process.env.JWT_REFRESH_SECRET_KEY!;
    
    // キーの強度チェック
    if (this.secretKey.length < 32) {
      throw new Error('JWT secret key must be at least 32 characters');
    }
  }

  generateAccessToken(payload: JWTPayload): string {
    return jwt.sign(
      {
        ...payload,
        type: 'access',
        iat: Math.floor(Date.now() / 1000),
      },
      this.secretKey,
      {
        expiresIn: '15m',
        issuer: 'game-review-service',
        audience: 'game-review-users',
        algorithm: 'HS256'
      }
    );
  }

  generateRefreshToken(userId: string): string {
    const jti = crypto.randomUUID(); // JWT ID for token revocation
    
    return jwt.sign(
      {
        userId,
        type: 'refresh',
        jti,
        iat: Math.floor(Date.now() / 1000),
      },
      this.refreshSecretKey,
      {
        expiresIn: '7d',
        issuer: 'game-review-service',
        audience: 'game-review-users',
        algorithm: 'HS256'
      }
    );
  }

  verifyAccessToken(token: string): JWTPayload {
    try {
      const decoded = jwt.verify(token, this.secretKey, {
        issuer: 'game-review-service',
        audience: 'game-review-users',
        algorithms: ['HS256']
      }) as JWTPayload;

      if (decoded.type !== 'access') {
        throw new Error('Invalid token type');
      }

      return decoded;
    } catch (error) {
      throw new UnauthorizedException('Invalid access token');
    }
  }
}
```

### 3.2. 認可制御

#### 3.2.1. ロールベース制御（RBAC）
```typescript
enum UserRole {
  USER = 'user',
  MODERATOR = 'moderator',
  ADMIN = 'admin'
}

enum Permission {
  READ_REVIEWS = 'read:reviews',
  CREATE_REVIEW = 'create:review',
  UPDATE_OWN_REVIEW = 'update:own_review',
  DELETE_OWN_REVIEW = 'delete:own_review',
  MODERATE_REVIEWS = 'moderate:reviews',
  MANAGE_USERS = 'manage:users',
  VIEW_ADMIN_DASHBOARD = 'view:admin_dashboard'
}

const RolePermissions: Record<UserRole, Permission[]> = {
  [UserRole.USER]: [
    Permission.READ_REVIEWS,
    Permission.CREATE_REVIEW,
    Permission.UPDATE_OWN_REVIEW,
    Permission.DELETE_OWN_REVIEW
  ],
  [UserRole.MODERATOR]: [
    ...RolePermissions[UserRole.USER],
    Permission.MODERATE_REVIEWS
  ],
  [UserRole.ADMIN]: [
    ...RolePermissions[UserRole.MODERATOR],
    Permission.MANAGE_USERS,
    Permission.VIEW_ADMIN_DASHBOARD
  ]
};

export class AuthorizationService {
  hasPermission(userRole: UserRole, requiredPermission: Permission): boolean {
    const userPermissions = RolePermissions[userRole];
    return userPermissions.includes(requiredPermission);
  }

  canAccessResource(user: User, resource: any, action: string): boolean {
    // リソース所有者チェック
    if (action.includes('own') && resource.userId === user.id) {
      return true;
    }

    // 年齢制限チェック
    if (user.isParentalConsentRequired && 
        user.parentalConsentStatus !== 'approved') {
      return false;
    }

    return this.hasPermission(user.role, `${action}:${resource.type}` as Permission);
  }
}
```

## 4. データ保護

### 4.1. 暗号化

#### 4.1.1. 保存時暗号化
```typescript
export class EncryptionService {
  private readonly algorithm = 'aes-256-gcm';
  private readonly keyDerivationIterations = 100000;

  constructor(private readonly masterKey: string) {}

  async encryptPersonalData(data: string, userId: string): Promise<EncryptedData> {
    // ユーザー固有のキー導出
    const salt = crypto.randomBytes(32);
    const key = crypto.pbkdf2Sync(
      this.masterKey + userId, 
      salt, 
      this.keyDerivationIterations, 
      32, 
      'sha256'
    );

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(this.algorithm, key);
    cipher.setAAD(Buffer.from(userId)); // Additional Authenticated Data

    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    return {
      encryptedData: encrypted,
      iv: iv.toString('hex'),
      salt: salt.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }

  async decryptPersonalData(
    encryptedData: EncryptedData, 
    userId: string
  ): Promise<string> {
    const salt = Buffer.from(encryptedData.salt, 'hex');
    const key = crypto.pbkdf2Sync(
      this.masterKey + userId, 
      salt, 
      this.keyDerivationIterations, 
      32, 
      'sha256'
    );

    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    
    const decipher = crypto.createDecipher(this.algorithm, key);
    decipher.setAAD(Buffer.from(userId));
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedData.encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}
```

#### 4.1.2. 通信時暗号化
```typescript
// TLS 1.3 設定
export const tlsConfig = {
  minVersion: 'TLSv1.3',
  maxVersion: 'TLSv1.3',
  ciphers: [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256'
  ].join(':'),
  honorCipherOrder: true,
  secureProtocol: 'TLSv1_3_method'
};

// HSTS設定
export const hstsConfig = {
  maxAge: 31536000, // 1年
  includeSubDomains: true,
  preload: true
};
```

### 4.2. 個人情報保護

#### 4.2.1. データ最小化
```typescript
interface DataCollectionPolicy {
  // 収集する最小限の情報
  required: {
    email: string;
    nickname: string;
    birthDate: string; // 年齢確認のため必須
  };
  
  optional: {
    profileImage?: string;
  };
  
  // 収集しない情報
  prohibited: [
    'realName',     // 実名
    'address',      // 住所
    'phoneNumber',  // 電話番号（MFA選択時のみ）
    'schoolName',   // 学校名
    'parentInfo'    // 保護者情報（同意確認メール以外）
  ];
}

export class PersonalDataService {
  async collectUserData(data: RegistrationData): Promise<SafeUserData> {
    // 年齢のみ計算、生年月日はハッシュ化して保存
    const age = this.calculateAge(data.birthDate);
    const birthDateHash = await bcrypt.hash(data.birthDate, 12);

    return {
      id: crypto.randomUUID(),
      email: data.email,
      nickname: data.nickname,
      age, // 数値のみ保存
      birthDateHash, // 元の日付は保存しない
      isMinor: age < 18,
      needsParentalConsent: age < 13,
      createdAt: new Date()
    };
  }

  async anonymizeUserData(userId: string): Promise<void> {
    // 退会時のデータ匿名化
    await this.userRepository.update(userId, {
      email: `deleted_${crypto.randomUUID()}@example.com`,
      nickname: '退会ユーザー',
      birthDateHash: null,
      profileImage: null,
      isDeleted: true
    });

    // 関連レビューの匿名化
    await this.reviewRepository.anonymizeUserReviews(userId);
  }
}
```

#### 4.2.2. データ保持ポリシー
```typescript
export class DataRetentionService {
  private readonly retentionPolicies = {
    userAccount: {
      activeUser: null, // 無期限（アクティブな限り）
      inactiveUser: 365 * 2, // 2年間非アクティブで削除検討
      deletedUser: 30 // 削除後30日で完全削除
    },
    reviewData: {
      publishedReview: null, // 公開レビューは永続保持
      draftReview: 90, // 下書きは90日で削除
      rejectedReview: 30 // 却下レビューは30日で削除
    },
    audioFiles: {
      published: 365 * 3, // 公開済み音声は3年保持
      processing: 7, // 処理中ファイルは7日で削除
      failed: 1 // 失敗ファイルは1日で削除
    },
    logs: {
      applicationLog: 90,
      auditLog: 365 * 7, // 監査ログは7年保持
      accessLog: 30
    }
  };

  async scheduleDataDeletion(): Promise<void> {
    // 毎日実行されるクリーンアップジョブ
    await this.cleanupInactiveUsers();
    await this.cleanupExpiredFiles();
    await this.cleanupOldLogs();
  }

  private async cleanupInactiveUsers(): Promise<void> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.retentionPolicies.userAccount.inactiveUser);

    const inactiveUsers = await this.userRepository.findInactive(cutoffDate);
    
    for (const user of inactiveUsers) {
      // 非アクティブユーザーに削除予告通知
      await this.notificationService.sendDeletionWarning(user.email);
      
      // 30日後に削除スケジュール
      await this.scheduleUserDeletion(user.id, 30);
    }
  }
}
```

## 5. コンテンツセキュリティ

### 5.1. 入力検証・サニタイゼーション

#### 5.1.1. API入力検証
```typescript
export class InputValidationService {
  // 音声ファイル検証
  async validateAudioFile(file: Express.Multer.File): Promise<ValidationResult> {
    const validations: ValidationCheck[] = [
      {
        name: 'fileSize',
        check: () => file.size <= 10 * 1024 * 1024, // 10MB
        error: 'ファイルサイズが大きすぎます（最大10MB）'
      },
      {
        name: 'mimeType',
        check: () => ['audio/mpeg', 'audio/wav', 'audio/m4a'].includes(file.mimetype),
        error: '対応していないファイル形式です'
      },
      {
        name: 'duration',
        check: async () => {
          const duration = await this.getAudioDuration(file.buffer);
          return duration <= 180; // 3分
        },
        error: '音声は3分以内にしてください'
      },
      {
        name: 'malwareCheck',
        check: async () => await this.scanForMalware(file.buffer),
        error: 'ファイルにセキュリティ上の問題があります'
      }
    ];

    for (const validation of validations) {
      const result = await validation.check();
      if (!result) {
        return { valid: false, error: validation.error };
      }
    }

    return { valid: true };
  }

  // テキスト入力サニタイゼーション
  sanitizeTextInput(input: string): string {
    return DOMPurify.sanitize(input, {
      ALLOWED_TAGS: [], // HTMLタグは一切許可しない
      ALLOWED_ATTR: [],
      KEEP_CONTENT: true
    }).trim();
  }

  // SQL インジェクション対策
  validateSQLParameters(params: Record<string, any>): boolean {
    const sqlPattern = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|EXECUTE)\b)/i;
    
    for (const [key, value] of Object.entries(params)) {
      if (typeof value === 'string' && sqlPattern.test(value)) {
        throw new BadRequestException(`Invalid parameter: ${key}`);
      }
    }
    
    return true;
  }
}
```

### 5.2. コンテンツモデレーション

#### 5.2.1. 多層フィルタリング
```typescript
export class ContentModerationService {
  async moderateContent(content: string): Promise<ModerationResult> {
    const moderationSteps: ModerationStep[] = [
      {
        name: 'profanityFilter',
        handler: () => this.checkProfanity(content),
        severity: 'high'
      },
      {
        name: 'personalInfoDetection',
        handler: () => this.detectPersonalInfo(content),
        severity: 'high'
      },
      {
        name: 'bullying Detection',
        handler: () => this.detectBullying(content),
        severity: 'high'
      },
      {
        name: 'ageAppropriatenessCheck',
        handler: () => this.checkAgeAppropriateness(content),
        severity: 'medium'
      },
      {
        name: 'openaiModeration',
        handler: () => this.openaiModeration(content),
        severity: 'medium'
      },
      {
        name: 'customClassifier',
        handler: () => this.customContentClassifier(content),
        severity: 'low'
      }
    ];

    let overallScore = 1.0;
    const flags: string[] = [];
    const suggestions: string[] = [];

    for (const step of moderationSteps) {
      try {
        const result = await step.handler();
        
        if (!result.passed) {
          flags.push(step.name);
          overallScore *= result.confidence;
          
          if (result.suggestions) {
            suggestions.push(...result.suggestions);
          }

          // 高重要度で失敗した場合は即座に却下
          if (step.severity === 'high' && result.confidence < 0.3) {
            return {
              approved: false,
              confidence: result.confidence,
              flags,
              reason: result.reason,
              suggestions
            };
          }
        }
      } catch (error) {
        console.error(`Moderation step ${step.name} failed:`, error);
        // エラー時はより厳しく判定
        overallScore *= 0.5;
      }
    }

    return {
      approved: overallScore > 0.7,
      confidence: overallScore,
      flags,
      suggestions: suggestions.length > 0 ? suggestions : this.getGenericSuggestions()
    };
  }

  private async checkProfanity(content: string): Promise<ModerationStepResult> {
    const profanityWords = await this.loadProfanityDatabase();
    const normalizedContent = this.normalizeText(content);
    
    for (const word of profanityWords) {
      if (normalizedContent.includes(word.word)) {
        return {
          passed: false,
          confidence: word.severity,
          reason: 'inappropriate_language',
          suggestions: word.alternatives || ['より丁寧な表現を使ってみてください']
        };
      }
    }
    
    return { passed: true, confidence: 1.0 };
  }

  private async detectPersonalInfo(content: string): Promise<ModerationStepResult> {
    const patterns = {
      phone: /(\d{2,4}-?\d{2,4}-?\d{4})/g,
      email: /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g,
      address: /(〒?\d{3}-?\d{4})|([都道府県][市区町村])/g,
      name: /(私の名前は|僕の名前は|名前は)(.+?)(です|だよ|！)/g
    };

    for (const [type, pattern] of Object.entries(patterns)) {
      if (pattern.test(content)) {
        return {
          passed: false,
          confidence: 0.1,
          reason: `personal_info_${type}`,
          suggestions: ['個人情報は含めないでください']
        };
      }
    }

    return { passed: true, confidence: 1.0 };
  }

  private async detectBullying(content: string): Promise<ModerationStepResult> {
    const bullyingPatterns = [
      /バカ|アホ|死ね|うざい|きもい/g,
      /みんなで無視/g,
      /仲間はずれ/g,
      /(誰々)はだめ|(誰々)なんて/g
    ];

    const bullyingScore = bullyingPatterns.reduce((score, pattern) => {
      const matches = content.match(pattern);
      return score + (matches ? matches.length * 0.3 : 0);
    }, 0);

    if (bullyingScore > 0.5) {
      return {
        passed: false,
        confidence: Math.max(0.1, 1 - bullyingScore),
        reason: 'potential_bullying',
        suggestions: [
          '他の人が傷つくような表現は避けましょう',
          'ゲームの良かった点を中心に話してみてください'
        ]
      };
    }

    return { passed: true, confidence: 1.0 };
  }

  private normalizeText(text: string): string {
    return text
      .toLowerCase()
      .replace(/[ぁ-ん]/g, match => String.fromCharCode(match.charCodeAt(0) + 0x60))
      .replace(/\s+/g, '')
      .replace(/[！!]/g, '!')
      .replace(/[？?]/g, '?');
  }
}
```

### 5.3. 音声コンテンツセキュリティ

#### 5.3.1. 音声分析セキュリティ
```typescript
export class AudioSecurityService {
  async analyzeAudioSecurity(audioBuffer: Buffer): Promise<AudioSecurityResult> {
    const results = await Promise.all([
      this.detectHiddenMessages(audioBuffer),
      this.analyzeAudioFingerprint(audioBuffer),
      this.checkAudioMetadata(audioBuffer),
      this.detectAudioDeepfake(audioBuffer)
    ]);

    return {
      isSecure: results.every(r => r.passed),
      threats: results.filter(r => !r.passed).map(r => r.threat),
      confidence: results.reduce((acc, r) => acc * r.confidence, 1.0)
    };
  }

  private async detectHiddenMessages(buffer: Buffer): Promise<SecurityCheckResult> {
    // ステガノグラフィー検出
    const spectralAnalysis = await this.performSpectralAnalysis(buffer);
    const suspiciousFrequencies = this.findAnomalousFrequencies(spectralAnalysis);
    
    if (suspiciousFrequencies.length > 0) {
      return {
        passed: false,
        threat: 'steganography_detected',
        confidence: 0.3
      };
    }

    return { passed: true, confidence: 1.0 };
  }

  private async detectAudioDeepfake(buffer: Buffer): Promise<SecurityCheckResult> {
    // AI生成音声検出（簡易版）
    const audioFeatures = await this.extractAudioFeatures(buffer);
    
    // 不自然な音声パターンを検出
    const unnaturalPatterns = [
      this.checkVoiceConsistency(audioFeatures),
      this.checkBreathingPatterns(audioFeatures),
      this.checkProsodyNaturalness(audioFeatures)
    ];

    const deepfakeScore = unnaturalPatterns.reduce((sum, score) => sum + score, 0) / unnaturalPatterns.length;
    
    if (deepfakeScore > 0.7) {
      return {
        passed: false,
        threat: 'potential_deepfake',
        confidence: deepfakeScore
      };
    }

    return { passed: true, confidence: 1 - deepfakeScore };
  }
}
```

## 6. インフラセキュリティ

### 6.1. ネットワークセキュリティ

#### 6.1.1. DDoS保護
```typescript
export class DDoSProtectionService {
  private readonly rateLimiters = new Map<string, RateLimiter>();
  
  constructor(
    private redisClient: Redis,
    private alertService: AlertService
  ) {}

  async checkRateLimit(
    clientId: string, 
    endpoint: string, 
    limit: RateLimitConfig
  ): Promise<RateLimitResult> {
    const key = `rate_limit:${clientId}:${endpoint}`;
    const window = limit.windowMs;
    const maxRequests = limit.max;

    const current = await this.redisClient.incr(key);
    
    if (current === 1) {
      await this.redisClient.expire(key, Math.ceil(window / 1000));
    }

    if (current > maxRequests) {
      // 異常なトラフィックを検出
      if (current > maxRequests * 10) {
        await this.handleSuspiciousActivity(clientId, endpoint, current);
      }

      return {
        allowed: false,
        remainingRequests: 0,
        resetTime: await this.redisClient.ttl(key) * 1000 + Date.now()
      };
    }

    return {
      allowed: true,
      remainingRequests: maxRequests - current,
      resetTime: await this.redisClient.ttl(key) * 1000 + Date.now()
    };
  }

  private async handleSuspiciousActivity(
    clientId: string, 
    endpoint: string, 
    requestCount: number
  ): Promise<void> {
    // アラート発信
    await this.alertService.sendSecurityAlert({
      type: 'potential_ddos',
      clientId,
      endpoint,
      requestCount,
      timestamp: new Date()
    });

    // 一時的なIP ブロック
    await this.blockClient(clientId, 3600); // 1時間ブロック
    
    // セキュリティログ記録
    await this.logSecurityEvent({
      event: 'rate_limit_exceeded',
      clientId,
      endpoint,
      requestCount,
      action: 'client_blocked'
    });
  }
}
```

#### 6.1.2. WAF ルール設定
```typescript
export const wafRules = {
  sqlInjection: {
    pattern: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC)\b)/i,
    action: 'block',
    severity: 'high'
  },
  xssAttempt: {
    pattern: /<script[^>]*>.*?<\/script>/gi,
    action: 'block',
    severity: 'high'
  },
  pathTraversal: {
    pattern: /\.\.[\/\\]/,
    action: 'block',
    severity: 'medium'
  },
  suspiciousUserAgent: {
    patterns: [
      /sqlmap/i,
      /nmap/i,
      /burpsuite/i,
      /nikto/i
    ],
    action: 'block',
    severity: 'medium'
  }
};
```

### 6.2. インフラ監視

#### 6.2.1. セキュリティ監視
```typescript
export class SecurityMonitoringService {
  private readonly alertThresholds = {
    failedLogins: {
      perMinute: 10,
      perHour: 50
    },
    suspiciousRequests: {
      perMinute: 100,
      perHour: 1000
    },
    dataExfiltration: {
      bytesPerMinute: 100 * 1024 * 1024, // 100MB
      requestsPerMinute: 1000
    }
  };

  async monitorSecurityEvents(): Promise<void> {
    const monitors = [
      this.monitorFailedLogins(),
      this.monitorSuspiciousRequests(),
      this.monitorDataAccess(),
      this.monitorSystemIntegrity()
    ];

    await Promise.all(monitors);
  }

  private async monitorFailedLogins(): Promise<void> {
    const failedLogins = await this.getFailedLoginsInWindow(60); // 1分間
    
    if (failedLogins.length > this.alertThresholds.failedLogins.perMinute) {
      await this.triggerSecurityAlert({
        type: 'excessive_failed_logins',
        count: failedLogins.length,
        timeWindow: '1minute',
        affectedIPs: [...new Set(failedLogins.map(l => l.ipAddress))]
      });
    }
  }

  private async monitorDataAccess(): Promise<void> {
    const dataAccess = await this.getDataAccessInWindow(60);
    const totalBytes = dataAccess.reduce((sum, access) => sum + access.bytesTransferred, 0);
    
    if (totalBytes > this.alertThresholds.dataExfiltration.bytesPerMinute) {
      await this.triggerSecurityAlert({
        type: 'potential_data_exfiltration',
        bytesTransferred: totalBytes,
        timeWindow: '1minute',
        topUsers: this.getTopDataUsers(dataAccess, 5)
      });
    }
  }

  private async triggerSecurityAlert(alert: SecurityAlert): Promise<void> {
    // 即座に対応チームに通知
    await this.notificationService.sendUrgentAlert(alert);
    
    // セキュリティログに記録
    await this.securityLogger.logAlert(alert);
    
    // 自動対応の実行
    await this.executeAutomaticResponse(alert);
  }

  private async executeAutomaticResponse(alert: SecurityAlert): Promise<void> {
    switch (alert.type) {
      case 'excessive_failed_logins':
        // 関連IPを一時ブロック
        for (const ip of alert.affectedIPs) {
          await this.blockIP(ip, 3600); // 1時間
        }
        break;
        
      case 'potential_data_exfiltration':
        // 関連ユーザーアカウントを一時停止
        for (const user of alert.topUsers) {
          await this.suspendUser(user.userId, '自動セキュリティ対応');
        }
        break;
    }
  }
}
```

## 7. プライバシー・法的コンプライアンス

### 7.1. COPPA準拠

#### 7.1.1. 年齢確認と保護者同意
```typescript
export class COPPAComplianceService {
  async handleMinorRegistration(
    userData: RegistrationData
  ): Promise<MinorRegistrationResult> {
    const age = this.calculateAge(userData.birthDate);
    
    if (age < 13) {
      // COPPA対象：保護者同意必須
      return await this.initiateParentalConsent(userData);
    } else if (age < 18) {
      // 13-17歳：簡易同意
      return await this.handleTeenRegistration(userData);
    } else {
      // 成人：通常登録
      return await this.handleAdultRegistration(userData);
    }
  }

  private async initiateParentalConsent(
    userData: RegistrationData
  ): Promise<MinorRegistrationResult> {
    // 1. 仮アカウント作成（機能制限付き）
    const tempUser = await this.createLimitedAccount(userData);
    
    // 2. 保護者同意フロー開始
    const consentToken = await this.generateConsentToken(tempUser.id);
    
    // 3. 保護者にメール送信
    await this.emailService.sendParentalConsentRequest({
      parentEmail: await this.requestParentEmail(),
      childNickname: userData.nickname,
      consentUrl: `${process.env.APP_URL}/parental-consent?token=${consentToken}`,
      serviceName: 'ゲームレビューサービス',
      dataCollectionPolicy: await this.getChildDataPolicy()
    });

    return {
      status: 'pending_parental_consent',
      userId: tempUser.id,
      message: '保護者の方にメールをお送りしました。同意確認後にサービスをご利用いただけます。'
    };
  }

  async processParentalConsent(
    token: string, 
    parentDecision: 'approve' | 'deny'
  ): Promise<ConsentResult> {
    const consentRecord = await this.validateConsentToken(token);
    
    if (!consentRecord || this.isTokenExpired(consentRecord)) {
      throw new BadRequestException('無効または期限切れの同意リンクです');
    }

    await this.recordParentalDecision({
      userId: consentRecord.userId,
      decision: parentDecision,
      timestamp: new Date(),
      ipAddress: this.getCurrentIP(),
      userAgent: this.getCurrentUserAgent()
    });

    if (parentDecision === 'approve') {
      // アカウント有効化
      await this.activateMinorAccount(consentRecord.userId);
      
      return {
        approved: true,
        message: 'お子様のアカウントが有効になりました'
      };
    } else {
      // アカウント削除
      await this.deleteMinorAccount(consentRecord.userId);
      
      return {
        approved: false,
        message: 'アカウントが削除されました'
      };
    }
  }

  private async getChildDataPolicy(): Promise<ChildDataPolicy> {
    return {
      dataCollected: [
        'ニックネーム（実名は収集しません）',
        'メールアドレス（ログイン用のみ）',
        '年齢（生年月日は保存しません）',
        'ゲームレビューの音声・テキスト'
      ],
      dataNotCollected: [
        '実名・住所・電話番号',
        '学校名・クラス情報', 
        '保護者情報（同意メール以外）',
        '位置情報・詳細な利用履歴'
      ],
      dataUsage: [
        'ゲームレビューの表示・共有',
        'AI分析による内容改善',
        '年齢に適したコンテンツ提供'
      ],
      dataSharing: '第三者への個人データ提供は行いません',
      dataRetention: 'アカウント削除時に関連データを削除します',
      parentRights: [
        'いつでもアカウント削除を要求できます',
        'お子様のデータ確認・修正ができます',
        'データ利用の停止を要求できます'
      ]
    };
  }
}
```

### 7.2. 個人情報保護法対応

#### 7.2.1. データ主体の権利
```typescript
export class PrivacyRightsService {
  // データポータビリティ（データ移行権）
  async exportUserData(userId: string): Promise<UserDataExport> {
    const user = await this.userRepository.findById(userId);
    const reviews = await this.reviewRepository.findByUserId(userId);
    const interactions = await this.interactionRepository.findByUserId(userId);

    return {
      exportDate: new Date(),
      userData: {
        nickname: user.nickname,
        email: user.email,
        createdAt: user.createdAt,
        profileImage: user.profileImageUrl
      },
      reviews: reviews.map(review => ({
        id: review.id,
        gameTitle: review.game.title,
        transcribedText: review.transcribedText,
        highlightText: review.highlightText,
        components: review.components,
        createdAt: review.createdAt
      })),
      interactions: {
        likes: interactions.likes.map(like => ({
          reviewId: like.reviewId,
          createdAt: like.createdAt
        })),
        comments: interactions.comments.map(comment => ({
          content: comment.content,
          reviewId: comment.reviewId,
          createdAt: comment.createdAt
        }))
      },
      format: 'JSON',
      notice: 'このデータは暗号化されており、本人確認後に提供されます'
    };
  }

  // データ削除権（忘れられる権利）
  async deleteUserData(
    userId: string, 
    deletionRequest: DeletionRequest
  ): Promise<DeletionResult> {
    // 1. 削除前の確認事項
    const confirmations = await this.getDataDeletionConfirmations(userId);
    
    if (!deletionRequest.confirmations.every(c => confirmations.includes(c))) {
      throw new BadRequestException('すべての確認事項に同意してください');
    }

    // 2. 段階的データ削除
    const deletionSteps = [
      () => this.anonymizeReviews(userId),
      () => this.deletePersonalData(userId),
      () => this.deleteInteractions(userId),
      () => this.deleteAudioFiles(userId),
      () => this.deleteLoginHistory(userId),
      () => this.markAccountDeleted(userId)
    ];

    const results = [];
    for (const step of deletionSteps) {
      try {
        await step();
        results.push({ status: 'success' });
      } catch (error) {
        results.push({ status: 'error', error: error.message });
      }
    }

    // 3. 削除ログ記録
    await this.logDataDeletion({
      userId,
      requestDate: new Date(),
      completionDate: new Date(),
      steps: results,
      requestedBy: deletionRequest.requestedBy
    });

    return {
      deleted: true,
      retentionPeriod: 30, // 30日間のみ復旧可能
      completionDate: new Date()
    };
  }

  // データ修正権
  async updateUserData(
    userId: string, 
    updateRequest: DataUpdateRequest
  ): Promise<UpdateResult> {
    // 修正可能なフィールドの制限
    const allowedFields = ['nickname', 'profileImage'];
    const requestedFields = Object.keys(updateRequest.data);
    
    const invalidFields = requestedFields.filter(
      field => !allowedFields.includes(field)
    );
    
    if (invalidFields.length > 0) {
      throw new BadRequestException(
        `修正できないフィールドが含まれています: ${invalidFields.join(', ')}`
      );
    }

    // データ修正の実行
    const updatedUser = await this.userRepository.update(userId, updateRequest.data);
    
    // 修正ログ記録
    await this.logDataUpdate({
      userId,
      changedFields: requestedFields,
      timestamp: new Date(),
      requestedBy: updateRequest.requestedBy
    });

    return {
      updated: true,
      changedFields: requestedFields,
      newData: this.sanitizeUserData(updatedUser)
    };
  }
}
```

## 8. インシデント対応

### 8.1. セキュリティインシデント対応計画

#### 8.1.1. インシデント分類と対応フロー
```typescript
enum IncidentSeverity {
  CRITICAL = 'critical',    // データ漏洩、システム侵害
  HIGH = 'high',           // 認証突破、マルウェア検出
  MEDIUM = 'medium',       // DDoS、不正アクセス試行
  LOW = 'low'             // 異常なトラフィック、設定ミス
}

export class IncidentResponseService {
  private readonly responseTeam = {
    securityLead: process.env.SECURITY_LEAD_EMAIL,
    techLead: process.env.TECH_LEAD_EMAIL,
    legal: process.env.LEGAL_TEAM_EMAIL,
    management: process.env.MANAGEMENT_EMAIL
  };

  async handleSecurityIncident(incident: SecurityIncident): Promise<void> {
    // 1. インシデントの初期評価
    const severity = await this.assessIncidentSeverity(incident);
    
    // 2. 即座の封じ込め
    await this.containIncident(incident, severity);
    
    // 3. チーム通知
    await this.notifyResponseTeam(incident, severity);
    
    // 4. 調査開始
    await this.initiateInvestigation(incident);
    
    // 5. 法的通知義務の確認
    if (severity === IncidentSeverity.CRITICAL) {
      await this.checkLegalNotificationRequirements(incident);
    }
  }

  private async containIncident(
    incident: SecurityIncident, 
    severity: IncidentSeverity
  ): Promise<void> {
    switch (severity) {
      case IncidentSeverity.CRITICAL:
        // システム部分停止
        await this.isolateAffectedSystems(incident.affectedSystems);
        // データベース読み取り専用モード
        await this.enableReadOnlyMode();
        // 緊急パッチ適用
        await this.applyEmergencyPatches(incident);
        break;
        
      case IncidentSeverity.HIGH:
        // 関連ユーザーアカウント一時停止
        await this.suspendAffectedAccounts(incident.affectedUsers);
        // セキュリティルール強化
        await this.enableStrictSecurityMode();
        break;
        
      case IncidentSeverity.MEDIUM:
        // IP ブロック、レート制限強化
        await this.blockSuspiciousIPs(incident.suspiciousIPs);
        await this.increaseRateLimit();
        break;
    }
  }

  async investigateDataBreach(breachIncident: DataBreachIncident): Promise<BreachReport> {
    const investigation = {
      timeline: await this.reconstructTimeline(breachIncident),
      affectedData: await this.identifyAffectedData(breachIncident),
      rootCause: await this.analyzeRootCause(breachIncident),
      impact: await this.assessImpact(breachIncident)
    };

    // 72時間以内の当局通知義務（GDPR準拠）
    if (investigation.impact.personalDataAffected > 0) {
      await this.scheduleRegulatoryNotification(investigation, 72);
    }

    // 影響を受けたユーザーへの通知
    if (investigation.impact.usersAffected.length > 0) {
      await this.notifyAffectedUsers(investigation.impact.usersAffected);
    }

    return {
      incidentId: breachIncident.id,
      investigation,
      containmentActions: breachIncident.containmentActions,
      remediationPlan: await this.createRemediationPlan(investigation),
      lessonsLearned: await this.documentLessonsLearned(investigation)
    };
  }
}
```

### 8.2. 復旧計画

#### 8.2.1. 事業継続性計画
```typescript
export class BusinessContinuityService {
  private readonly recoveryObjectives = {
    rto: 4 * 60 * 60 * 1000, // 4時間（Recovery Time Objective）
    rpo: 1 * 60 * 60 * 1000  // 1時間（Recovery Point Objective）
  };

  async executeDisasterRecovery(disaster: DisasterEvent): Promise<RecoveryStatus> {
    const recoveryPlan = await this.getRecoveryPlan(disaster.type);
    
    // 1. 被害状況評価
    const damage = await this.assessDamage(disaster);
    
    // 2. 復旧手順実行
    const recoverySteps = await this.executeRecoverySteps(recoveryPlan, damage);
    
    // 3. サービス状態監視
    const serviceStatus = await this.monitorServiceRecovery();
    
    return {
      disasterId: disaster.id,
      recoveryStarted: new Date(),
      estimatedCompletion: new Date(Date.now() + this.recoveryObjectives.rto),
      currentStatus: serviceStatus,
      completedSteps: recoverySteps.filter(s => s.status === 'completed'),
      pendingSteps: recoverySteps.filter(s => s.status === 'pending')
    };
  }

  private async executeRecoverySteps(
    plan: RecoveryPlan, 
    damage: DamageAssessment
  ): Promise<RecoveryStep[]> {
    const steps: RecoveryStep[] = [
      {
        id: 'infrastructure',
        name: 'インフラ復旧',
        priority: 1,
        estimatedTime: 30 * 60 * 1000, // 30分
        action: () => this.recoverInfrastructure(damage)
      },
      {
        id: 'database',
        name: 'データベース復旧',
        priority: 2,
        estimatedTime: 60 * 60 * 1000, // 1時間
        action: () => this.recoverDatabase(damage)
      },
      {
        id: 'application',
        name: 'アプリケーション復旧',
        priority: 3,
        estimatedTime: 45 * 60 * 1000, // 45分
        action: () => this.recoverApplication(damage)
      },
      {
        id: 'verification',
        name: '動作確認',
        priority: 4,
        estimatedTime: 15 * 60 * 1000, // 15分
        action: () => this.verifySystemIntegrity()
      }
    ];

    // 優先度順に実行
    for (const step of steps.sort((a, b) => a.priority - b.priority)) {
      try {
        step.status = 'in_progress';
        step.startTime = new Date();
        
        await step.action();
        
        step.status = 'completed';
        step.endTime = new Date();
      } catch (error) {
        step.status = 'failed';
        step.error = error.message;
        
        // クリティカルステップの失敗時は手動介入
        if (step.priority <= 2) {
          await this.escalateToManualRecovery(step, error);
        }
      }
    }

    return steps;
  }
}
```

## 9. 監査・コンプライアンス

### 9.1. セキュリティ監査

#### 9.1.1. 定期監査項目
```typescript
export class SecurityAuditService {
  private readonly auditSchedule = {
    daily: [
      'access_logs_review',
      'failed_login_analysis',
      'system_health_check'
    ],
    weekly: [
      'user_permission_review',
      'api_usage_analysis',
      'content_moderation_review'
    ],
    monthly: [
      'vulnerability_scan',
      'penetration_testing',
      'compliance_check'
    ],
    quarterly: [
      'security_policy_review',
      'incident_response_test',
      'business_continuity_test'
    ]
  };

  async performDailyAudit(): Promise<DailyAuditReport> {
    const auditResults = await Promise.all([
      this.reviewAccessLogs(),
      this.analyzeFailedLogins(),
      this.checkSystemHealth()
    ]);

    const report: DailyAuditReport = {
      date: new Date(),
      results: auditResults,
      riskScore: this.calculateRiskScore(auditResults),
      recommendations: this.generateRecommendations(auditResults),
      requiresAttention: auditResults.some(r => r.severity === 'high')
    };

    if (report.requiresAttention) {
      await this.notifySecurityTeam(report);
    }

    return report;
  }

  private async reviewAccessLogs(): Promise<AuditResult> {
    const logs = await this.getAccessLogsInWindow(24 * 60 * 60 * 1000); // 24時間
    
    const suspiciousActivities = [
      ...this.detectUnusualAccessPatterns(logs),
      ...this.detectPrivilegeEscalation(logs),
      ...this.detectDataExfiltration(logs)
    ];

    return {
      category: 'access_control',
      severity: suspiciousActivities.length > 0 ? 'high' : 'low',
      findings: suspiciousActivities,
      recommendation: suspiciousActivities.length > 0 
        ? '異常なアクセスパターンが検出されました。詳細調査を推奨します。'
        : 'アクセスログに問題はありません。'
    };
  }

  async performVulnerabilityAssessment(): Promise<VulnerabilityReport> {
    const scanners = [
      this.runNpmAudit(),
      this.runContainerScan(),
      this.runInfrastructureScan(),
      this.runApplicationScan()
    ];

    const results = await Promise.allSettled(scanners);
    const vulnerabilities = results
      .filter(r => r.status === 'fulfilled')
      .flatMap(r => r.value.vulnerabilities);

    return {
      scanDate: new Date(),
      totalVulnerabilities: vulnerabilities.length,
      criticalCount: vulnerabilities.filter(v => v.severity === 'critical').length,
      highCount: vulnerabilities.filter(v => v.severity === 'high').length,
      mediumCount: vulnerabilities.filter(v => v.severity === 'medium').length,
      lowCount: vulnerabilities.filter(v => v.severity === 'low').length,
      vulnerabilities: vulnerabilities.sort((a, b) => 
        this.getSeverityScore(b.severity) - this.getSeverityScore(a.severity)
      ),
      remediationPlan: await this.createRemediationPlan(vulnerabilities)
    };
  }
}
```

### 9.2. コンプライアンス報告

#### 9.2.1. 定期コンプライアンス報告
```typescript
export class ComplianceReportingService {
  async generateMonthlyComplianceReport(): Promise<ComplianceReport> {
    const [
      coppaCompliance,
      privacyCompliance,
      securityCompliance,
      contentCompliance
    ] = await Promise.all([
      this.assessCOPPACompliance(),
      this.assessPrivacyCompliance(),
      this.assessSecurityCompliance(),
      this.assessContentCompliance()
    ]);

    return {
      reportPeriod: this.getReportPeriod(),
      overallScore: this.calculateOverallComplianceScore([
        coppaCompliance,
        privacyCompliance,
        securityCompliance,
        contentCompliance
      ]),
      coppaCompliance,
      privacyCompliance,
      securityCompliance,
      contentCompliance,
      actionItems: this.generateActionItems([
        coppaCompliance,
        privacyCompliance,
        securityCompliance,
        contentCompliance
      ]),
      nextReviewDate: this.getNextReviewDate()
    };
  }

  private async assessCOPPACompliance(): Promise<COPPAComplianceAssessment> {
    const metrics = await this.getCOPPAMetrics();
    
    return {
      parental ConsentRate: metrics.parentalConsentApproved / metrics.totalMinorRegistrations,
      dataMinimizationScore: await this.assessDataMinimization(),
      deletionComplianceRate: metrics.completedDeletions / metrics.requestedDeletions,
      notificationComplianceScore: await this.assessNotificationCompliance(),
      overallScore: 0, // 計算される
      issues: await this.identifyCOPPAIssues(metrics),
      recommendations: await this.generateCOPPARecommendations(metrics)
    };
  }

  private async assessSecurityCompliance(): Promise<SecurityComplianceAssessment> {
    const securityMetrics = await this.getSecurityMetrics();
    
    return {
      encryptionCompliance: await this.verifyEncryptionStandards(),
      accessControlCompliance: await this.verifyAccessControls(),
      incidentResponseCompliance: await this.verifyIncidentResponse(),
      vulnerabilityManagement: await this.assessVulnerabilityManagement(),
      backupAndRecovery: await this.verifyBackupProcedures(),
      auditingCompliance: await this.verifyAuditingProcedures(),
      overallScore: 0, // 計算される
      gaps: await this.identifySecurityGaps(),
      recommendations: await this.generateSecurityRecommendations()
    };
  }
}
```

## 10. セキュリティガイドライン

### 10.1. 開発セキュリティガイドライン

#### 10.1.1. セキュアコーディング規約
```typescript
// セキュアコーディングのベストプラクティス

// ❌ 悪い例：SQLインジェクション脆弱性
const getUserReviews = async (userId: string) => {
  const query = `SELECT * FROM reviews WHERE user_id = '${userId}'`;
  return await db.query(query);
};

// ✅ 良い例：パラメータ化クエリ
const getUserReviews = async (userId: string) => {
  return await db.query(
    'SELECT * FROM reviews WHERE user_id = $1',
    [userId]
  );
};

// ❌ 悪い例：認証なしの機密操作
const deleteReview = async (reviewId: string) => {
  return await reviewRepository.delete(reviewId);
};

// ✅ 良い例：適切な認証・認可
const deleteReview = async (reviewId: string, currentUser: User) => {
  const review = await reviewRepository.findById(reviewId);
  
  if (!review) {
    throw new NotFoundException('レビューが見つかりません');
  }
  
  if (review.userId !== currentUser.id && !currentUser.hasRole('admin')) {
    throw new ForbiddenException('このレビューを削除する権限がありません');
  }
  
  return await reviewRepository.delete(reviewId);
};

// ❌ 悪い例：機密情報の漏洩
const getUser = async (userId: string) => {
  return await userRepository.findById(userId); // パスワードハッシュも含む
};

// ✅ 良い例：必要最小限の情報のみ返却
const getUser = async (userId: string) => {
  const user = await userRepository.findById(userId);
  return {
    id: user.id,
    nickname: user.nickname,
    profileImageUrl: user.profileImageUrl,
    createdAt: user.createdAt
  };
};
```

### 10.2. 運用セキュリティガイドライン

#### 10.2.1. 本番環境セキュリティチェックリスト
```markdown
## デプロイ前セキュリティチェックリスト

### 認証・認可
- [ ] すべてのAPIエンドポイントに適切な認証が実装されている
- [ ] JWTトークンの署名検証が正しく動作する
- [ ] ロールベースアクセス制御が正しく実装されている
- [ ] セッション管理が適切に実装されている

### 入力検証
- [ ] すべてのユーザー入力に対してバリデーションが実装されている
- [ ] SQLインジェクション対策が実装されている
- [ ] XSS対策が実装されている
- [ ] ファイルアップロードの検証が実装されている

### データ保護
- [ ] 個人情報の暗号化が実装されている
- [ ] データベース接続文字列が暗号化されている
- [ ] APIキーが環境変数で管理されている
- [ ] ログに機密情報が出力されていない

### インフラセキュリティ
- [ ] TLS 1.3が有効になっている
- [ ] セキュリティヘッダーが設定されている
- [ ] レート制限が実装されている
- [ ] WAFルールが設定されている

### 監視・ログ
- [ ] セキュリティイベントのログが設定されている
- [ ] 異常検知アラートが設定されている
- [ ] 監査ログが適切に記録されている
- [ ] インシデント対応手順が文書化されている

### コンプライアンス
- [ ] COPPA要件が満たされている
- [ ] プライバシーポリシーが更新されている
- [ ] データ保持ポリシーが実装されている
- [ ] ユーザーの権利行使機能が実装されている
```

---

**セキュリティ要件書承認:**
- セキュリティ責任者: ___________
- 法務担当者: ___________
- プロダクトオーナー: ___________

**次回レビュー予定日:** 2025年10月14日

**緊急連絡先:**
- セキュリティチーム: security@game-review-service.com
- インシデント対応: incident-response@game-review-service.com