# ゲームレビューサービス 詳細設計書

**文書バージョン:** 1.0  
**作成日:** 2025年7月14日  
**作成者:** 開発チーム  

## 1. モジュール詳細設計

### 1.1. 認証モジュール (Authentication Module)

#### 1.1.1. クラス設計

```typescript
// interfaces/auth.interface.ts
export interface IAuthService {
  register(userData: RegisterRequest): Promise<AuthResponse>;
  login(credentials: LoginRequest): Promise<AuthResponse>;
  logout(userId: string): Promise<void>;
  refreshToken(refreshToken: string): Promise<TokenResponse>;
  requestParentalConsent(userId: string): Promise<void>;
  verifyParentalConsent(token: string): Promise<void>;
}

export interface RegisterRequest {
  email: string;
  password: string;
  nickname: string;
  birthDate: string; // ISO date string
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface AuthResponse {
  user: User;
  tokens: {
    accessToken: string;
    refreshToken: string;
  };
}

// services/auth.service.ts
@Injectable()
export class AuthService implements IAuthService {
  constructor(
    private userRepository: UserRepository,
    private jwtService: JwtService,
    private emailService: EmailService,
    private redisService: RedisService
  ) {}

  async register(userData: RegisterRequest): Promise<AuthResponse> {
    // 1. 入力値検証
    await this.validateRegistrationData(userData);
    
    // 2. 年齢計算と保護者同意判定
    const age = this.calculateAge(userData.birthDate);
    const needsParentalConsent = age < 13;
    
    // 3. パスワードハッシュ化
    const hashedPassword = await bcrypt.hash(userData.password, 12);
    
    // 4. ユーザー作成
    const user = await this.userRepository.create({
      email: userData.email,
      passwordHash: hashedPassword,
      nickname: userData.nickname,
      birthDate: new Date(userData.birthDate),
      isParentalConsentRequired: needsParentalConsent,
      parentalConsentStatus: needsParentalConsent ? 'pending' : 'approved'
    });
    
    // 5. 保護者同意メール送信（必要な場合）
    if (needsParentalConsent) {
      await this.requestParentalConsent(user.id);
    }
    
    // 6. JWT生成
    const tokens = await this.generateTokens(user);
    
    return {
      user: this.sanitizeUser(user),
      tokens
    };
  }

  async login(credentials: LoginRequest): Promise<AuthResponse> {
    // 1. ユーザー検索
    const user = await this.userRepository.findByEmail(credentials.email);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    
    // 2. パスワード検証
    const isValidPassword = await bcrypt.compare(
      credentials.password, 
      user.passwordHash
    );
    if (!isValidPassword) {
      throw new UnauthorizedException('Invalid credentials');
    }
    
    // 3. アカウント状態確認
    if (user.isParentalConsentRequired && 
        user.parentalConsentStatus !== 'approved') {
      throw new ForbiddenException('Parental consent required');
    }
    
    // 4. JWT生成
    const tokens = await this.generateTokens(user);
    
    // 5. ログイン履歴記録
    await this.recordLoginHistory(user.id);
    
    return {
      user: this.sanitizeUser(user),
      tokens
    };
  }

  private async generateTokens(user: User): Promise<TokenResponse> {
    const payload: JWTPayload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      isParentalConsentRequired: user.isParentalConsentRequired
    };
    
    const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
    const refreshToken = this.jwtService.sign(
      { userId: user.id }, 
      { expiresIn: '7d' }
    );
    
    // Refresh token をRedisに保存
    await this.redisService.set(
      `refresh_token:${user.id}`, 
      refreshToken, 
      7 * 24 * 60 * 60 // 7日間
    );
    
    return { accessToken, refreshToken };
  }
}
```

#### 1.1.2. ミドルウェア設計

```typescript
// middleware/auth.middleware.ts
export class AuthMiddleware implements NestMiddleware {
  constructor(
    private jwtService: JwtService,
    private userRepository: UserRepository
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    try {
      // 1. トークン抽出
      const token = this.extractTokenFromHeader(req);
      if (!token) {
        throw new UnauthorizedException('Token not found');
      }

      // 2. トークン検証
      const payload = this.jwtService.verify(token) as JWTPayload;
      
      // 3. ユーザー存在確認
      const user = await this.userRepository.findById(payload.userId);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // 4. リクエストオブジェクトにユーザー情報追加
      req.user = user;
      next();
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
```

### 1.2. レビューモジュール (Review Module)

#### 1.2.1. レビュー作成フロー

```typescript
// services/review.service.ts
export class ReviewService {
  constructor(
    private reviewRepository: ReviewRepository,
    private aiService: AiService,
    private fileUploadService: FileUploadService,
    private moderationService: ModerationService
  ) {}

  async createReview(
    userId: string, 
    reviewData: CreateReviewRequest
  ): Promise<Review> {
    // 1. 音声ファイルアップロード
    const audioUrl = await this.fileUploadService.uploadAudio(
      reviewData.audioFile
    );

    // 2. 音声テキスト変換
    const transcription = await this.aiService.transcribeAudio(audioUrl);

    // 3. コンテンツ審査
    const moderationResult = await this.moderationService.moderateContent(
      transcription
    );
    
    if (!moderationResult.isApproved) {
      throw new BadRequestException('Content violates community guidelines');
    }

    // 4. AI分析による成分グラフ生成
    const components = await this.aiService.generateComponents(
      transcription,
      reviewData.gameId
    );

    // 5. ハイライトテキスト抽出
    const highlightText = await this.aiService.extractHighlight(
      transcription
    );

    // 6. レビュー保存
    const review = await this.reviewRepository.create({
      userId,
      gameId: reviewData.gameId,
      audioFileUrl: audioUrl,
      audioDuration: reviewData.audioDuration,
      transcribedText: transcription,
      highlightText,
      playTimeHours: reviewData.playTimeHours,
      status: 'approved'
    });

    // 7. 成分データ保存
    await this.reviewRepository.createComponents(review.id, components);

    return review;
  }

  async updateReviewComponents(
    reviewId: string,
    userId: string,
    components: ReviewComponents
  ): Promise<void> {
    // 1. レビュー所有者確認
    const review = await this.reviewRepository.findById(reviewId);
    if (review.userId !== userId) {
      throw new ForbiddenException('Not authorized to update this review');
    }

    // 2. 成分データ更新
    await this.reviewRepository.updateComponents(reviewId, {
      ...components,
      isAiGenerated: false // ユーザーが編集したことを記録
    });
  }

  async getReviewsFeed(
    userId: string,
    pagination: PaginationOptions
  ): Promise<PaginatedResult<Review>> {
    // 1. ユーザーの好み分析
    const userPreferences = await this.analyzeUserPreferences(userId);

    // 2. レコメンドアルゴリズム適用
    const reviews = await this.reviewRepository.findRecommended(
      userPreferences,
      pagination
    );

    // 3. 追加情報付与（いいね状態、コメント数など）
    const enrichedReviews = await this.enrichReviewsData(reviews, userId);

    return {
      data: enrichedReviews,
      meta: {
        total: reviews.length,
        page: pagination.page,
        limit: pagination.limit
      }
    };
  }
}
```

#### 1.2.2. レビューリポジトリ設計

```typescript
// repositories/review.repository.ts
export class ReviewRepository {
  constructor(private prisma: PrismaService) {}

  async create(data: CreateReviewData): Promise<Review> {
    return this.prisma.review.create({
      data,
      include: {
        user: {
          select: { id: true, nickname: true, profileImageUrl: true }
        },
        game: true,
        components: true,
        _count: {
          select: { likes: true, comments: true }
        }
      }
    });
  }

  async findRecommended(
    preferences: UserPreferences,
    pagination: PaginationOptions
  ): Promise<Review[]> {
    // 複雑なレコメンドクエリ
    return this.prisma.$queryRaw`
      SELECT r.*, 
             u.nickname, u.profile_image_url,
             g.title as game_title, g.image_url as game_image,
             rc.*,
             COUNT(l.id) as like_count,
             COUNT(c.id) as comment_count,
             -- レコメンドスコア計算
             (
               ABS(rc.story_score - ${preferences.storyPreference}) * 0.2 +
               ABS(rc.character_score - ${preferences.characterPreference}) * 0.2 +
               ABS(rc.music_score - ${preferences.musicPreference}) * 0.15 +
               ABS(rc.controls_score - ${preferences.controlsPreference}) * 0.15 +
               ABS(rc.multiplayer_score - ${preferences.multiplayerPreference}) * 0.15 +
               ABS(rc.solo_score - ${preferences.soloPreference}) * 0.15
             ) as recommendation_score
      FROM reviews r
      JOIN users u ON r.user_id = u.id
      JOIN games g ON r.game_id = g.id
      JOIN review_components rc ON r.id = rc.review_id
      LEFT JOIN likes l ON r.id = l.review_id
      LEFT JOIN comments c ON r.id = c.review_id
      WHERE r.status = 'approved'
      GROUP BY r.id, u.id, g.id, rc.id
      ORDER BY recommendation_score ASC, r.created_at DESC
      LIMIT ${pagination.limit}
      OFFSET ${(pagination.page - 1) * pagination.limit}
    `;
  }
}
```

### 1.3. AI分析モジュール (AI Analysis Module)

#### 1.3.1. OpenAI API 統合

```typescript
// services/ai.service.ts
export class AiService {
  private openai: OpenAI;

  constructor(
    private configService: ConfigService,
    private cacheService: CacheService
  ) {
    this.openai = new OpenAI({
      apiKey: this.configService.get('OPENAI_API_KEY')
    });
  }

  async transcribeAudio(audioUrl: string): Promise<string> {
    try {
      // 1. キャッシュ確認
      const cacheKey = `transcription:${this.hashUrl(audioUrl)}`;
      const cached = await this.cacheService.get(cacheKey);
      if (cached) return cached;

      // 2. 音声ファイルダウンロード
      const audioBuffer = await this.downloadAudioFile(audioUrl);

      // 3. Whisper API呼び出し
      const transcription = await this.openai.audio.transcriptions.create({
        file: audioBuffer,
        model: 'whisper-1',
        language: 'ja',
        response_format: 'text'
      });

      // 4. 結果キャッシュ
      await this.cacheService.set(cacheKey, transcription, 3600); // 1時間

      return transcription;
    } catch (error) {
      throw new InternalServerErrorException('Audio transcription failed');
    }
  }

  async generateComponents(
    transcribedText: string,
    gameId: string
  ): Promise<ReviewComponents> {
    try {
      // 1. ゲーム情報取得
      const gameInfo = await this.getGameInfo(gameId);

      // 2. プロンプト構築
      const prompt = this.buildComponentsPrompt(transcribedText, gameInfo);

      // 3. GPT-4 分析
      const completion = await this.openai.chat.completions.create({
        model: 'gpt-4',
        messages: [
          {
            role: 'system',
            content: 'あなたは子供のゲームレビューを分析する専門家です。'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 0.3,
        max_tokens: 500
      });

      // 4. レスポンス解析
      const result = JSON.parse(completion.choices[0].message.content);
      
      return {
        storyScore: Math.max(0, Math.min(10, result.story || 5)),
        characterScore: Math.max(0, Math.min(10, result.character || 5)),
        musicScore: Math.max(0, Math.min(10, result.music || 5)),
        controlsScore: Math.max(0, Math.min(10, result.controls || 5)),
        multiplayerScore: Math.max(0, Math.min(10, result.multiplayer || 5)),
        soloScore: Math.max(0, Math.min(10, result.solo || 5))
      };
    } catch (error) {
      // フォールバック: デフォルト値を返す
      return this.getDefaultComponents();
    }
  }

  private buildComponentsPrompt(text: string, gameInfo: any): string {
    return `
ゲーム「${gameInfo.title}」についての以下のレビューを分析してください：

「${text}」

以下の6つの要素について、0-10のスコアで評価してください：
1. story（ストーリーの面白さ）
2. character（キャラクターの魅力）
3. music（音楽・サウンドの質）
4. controls（操作性）
5. multiplayer（みんなでワイワイ度）
6. solo（ひとりでコツコツ度）

レスポンスは以下のJSON形式で返してください：
{
  "story": 数値,
  "character": 数値,
  "music": 数値,
  "controls": 数値,
  "multiplayer": 数値,
  "solo": 数値,
  "reasoning": "分析の根拠を簡潔に"
}
    `;
  }
}
```

### 1.4. コンテンツ審査モジュール (Content Moderation Module)

#### 1.4.1. 多層審査システム

```typescript
// services/moderation.service.ts
export class ModerationService {
  constructor(
    private openai: OpenAI,
    private ngWordService: NgWordService,
    private reportRepository: ReportRepository
  ) {}

  async moderateContent(content: string): Promise<ModerationResult> {
    // 1. NGワードチェック
    const ngWordResult = await this.ngWordService.check(content);
    if (!ngWordResult.passed) {
      return {
        isApproved: false,
        reason: 'inappropriate_language',
        suggestions: ngWordResult.suggestions
      };
    }

    // 2. OpenAI Moderation API
    const moderation = await this.openai.moderations.create({
      input: content
    });

    if (moderation.results[0].flagged) {
      return {
        isApproved: false,
        reason: 'ai_flagged',
        categories: moderation.results[0].categories
      };
    }

    // 3. カスタム分類器（年齢適合性）
    const ageAppropriateResult = await this.checkAgeAppropriateness(content);
    if (!ageAppropriateResult.isAppropriate) {
      return {
        isApproved: false,
        reason: 'age_inappropriate',
        score: ageAppropriateResult.score
      };
    }

    return {
      isApproved: true,
      confidence: 0.95
    };
  }

  private async checkAgeAppropriateness(content: string): Promise<{
    isAppropriate: boolean;
    score: number;
  }> {
    // カスタム年齢適合性チェックロジック
    const inappropriatePatterns = [
      /暴力的/g,
      /恐怖/g,
      /怖い/g,
      /残酷/g
    ];

    let score = 1.0;
    for (const pattern of inappropriatePatterns) {
      const matches = content.match(pattern);
      if (matches) {
        score -= matches.length * 0.1;
      }
    }

    return {
      isAppropriate: score > 0.7,
      score: Math.max(0, score)
    };
  }
}

// services/ngword.service.ts
export class NgWordService {
  private ngWords: Set<string>;
  private inappropriatePatterns: RegExp[];

  constructor() {
    this.loadNgWords();
    this.loadPatterns();
  }

  async check(text: string): Promise<NgWordCheckResult> {
    const normalizedText = this.normalizeText(text);
    
    // 1. 完全一致チェック
    for (const word of this.ngWords) {
      if (normalizedText.includes(word)) {
        return {
          passed: false,
          foundWords: [word],
          suggestions: this.getSuggestions(word)
        };
      }
    }

    // 2. パターンマッチング
    for (const pattern of this.inappropriatePatterns) {
      if (pattern.test(normalizedText)) {
        return {
          passed: false,
          foundWords: ['パターンマッチ'],
          suggestions: ['より建設的な表現を使ってみてください']
        };
      }
    }

    return { passed: true };
  }

  private normalizeText(text: string): string {
    return text
      .toLowerCase()
      .replace(/[ぁ-ん]/g, (match) => String.fromCharCode(match.charCodeAt(0) + 0x60))
      .replace(/\s+/g, '');
  }

  private getSuggestions(word: string): string[] {
    const suggestionMap: Record<string, string[]> = {
      'つまらない': ['自分には合わなかった', '期待と違った'],
      'クソゲー': ['期待していたものと違った', '改善の余地がある'],
      'バグだらけ': ['技術的な問題があった', '安定性に課題がある']
    };

    return suggestionMap[word] || ['より建設的な表現を考えてみてください'];
  }
}
```

### 1.5. ファイルアップロードモジュール (File Upload Module)

#### 1.5.1. 音声ファイル処理

```typescript
// services/file-upload.service.ts
export class FileUploadService {
  constructor(
    private s3Client: S3Client,
    private configService: ConfigService
  ) {}

  async uploadAudio(file: Express.Multer.File): Promise<string> {
    // 1. ファイル検証
    await this.validateAudioFile(file);

    // 2. 音声ファイル最適化
    const optimizedBuffer = await this.optimizeAudio(file.buffer);

    // 3. ファイル名生成
    const fileName = this.generateFileName(file.originalname, 'audio');

    // 4. S3アップロード
    const uploadResult = await this.s3Client.send(new PutObjectCommand({
      Bucket: this.configService.get('AWS_S3_BUCKET'),
      Key: fileName,
      Body: optimizedBuffer,
      ContentType: 'audio/mpeg',
      ServerSideEncryption: 'AES256'
    }));

    // 5. URL生成
    return `https://${this.configService.get('AWS_S3_BUCKET')}.s3.amazonaws.com/${fileName}`;
  }

  private async validateAudioFile(file: Express.Multer.File): Promise<void> {
    // 1. ファイルサイズチェック (最大10MB)
    if (file.size > 10 * 1024 * 1024) {
      throw new BadRequestException('Audio file too large');
    }

    // 2. ファイル形式チェック
    const allowedMimeTypes = ['audio/mpeg', 'audio/wav', 'audio/m4a'];
    if (!allowedMimeTypes.includes(file.mimetype)) {
      throw new BadRequestException('Invalid audio format');
    }

    // 3. 音声長さチェック (最大3分)
    const duration = await this.getAudioDuration(file.buffer);
    if (duration > 180) { // 3分 = 180秒
      throw new BadRequestException('Audio too long (max 3 minutes)');
    }
  }

  private async optimizeAudio(buffer: Buffer): Promise<Buffer> {
    // FFMPEGを使用した音声最適化
    return new Promise((resolve, reject) => {
      const ffmpeg = spawn('ffmpeg', [
        '-i', 'pipe:0',
        '-acodec', 'mp3',
        '-ab', '128k',
        '-ar', '44100',
        '-f', 'mp3',
        'pipe:1'
      ]);

      const chunks: Buffer[] = [];

      ffmpeg.stdout.on('data', (chunk) => {
        chunks.push(chunk);
      });

      ffmpeg.stdout.on('end', () => {
        resolve(Buffer.concat(chunks));
      });

      ffmpeg.on('error', reject);

      ffmpeg.stdin.write(buffer);
      ffmpeg.stdin.end();
    });
  }

  private generateFileName(originalName: string, type: string): string {
    const timestamp = Date.now();
    const randomString = Math.random().toString(36).substring(7);
    const extension = path.extname(originalName);
    
    return `${type}/${timestamp}-${randomString}${extension}`;
  }
}
```

## 2. データベース詳細設計

### 2.1. Prisma スキーマ設計

```prisma
// prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id                          String    @id @default(cuid())
  email                       String    @unique
  passwordHash                String    @map("password_hash")
  nickname                    String
  birthDate                   DateTime  @map("birth_date")
  profileImageUrl             String?   @map("profile_image_url")
  isParentalConsentRequired   Boolean   @default(false) @map("is_parental_consent_required")
  parentalConsentStatus       ConsentStatus @default(PENDING) @map("parental_consent_status")
  role                        UserRole  @default(USER)
  isActive                    Boolean   @default(true) @map("is_active")
  lastLoginAt                 DateTime? @map("last_login_at")
  createdAt                   DateTime  @default(now()) @map("created_at")
  updatedAt                   DateTime  @updatedAt @map("updated_at")

  // Relations
  reviews                     Review[]
  likes                       Like[]
  comments                    Comment[]
  reports                     Report[] @relation("UserReports")
  reportedReviews            Report[] @relation("ReportedReviews")
  loginHistory               LoginHistory[]

  @@map("users")
}

model Game {
  id              String    @id @default(cuid())
  title           String
  platform        String
  genre           String?
  developer       String?
  publisher       String?
  releaseDate     DateTime? @map("release_date")
  imageUrl        String?   @map("image_url")
  description     String?
  ageRating       String?   @map("age_rating")
  isActive        Boolean   @default(true) @map("is_active")
  createdAt       DateTime  @default(now()) @map("created_at")
  updatedAt       DateTime  @updatedAt @map("updated_at")

  // Relations
  reviews         Review[]

  @@map("games")
}

model Review {
  id                String      @id @default(cuid())
  userId            String      @map("user_id")
  gameId            String      @map("game_id")
  audioFileUrl      String      @map("audio_file_url")
  audioDuration     Int         @map("audio_duration") // seconds
  transcribedText   String?     @map("transcribed_text")
  highlightText     String?     @map("highlight_text")
  playTimeHours     Int?        @map("play_time_hours")
  status            ReviewStatus @default(PENDING)
  moderationFlags   Json?       @map("moderation_flags")
  isAiProcessed     Boolean     @default(false) @map("is_ai_processed")
  viewCount         Int         @default(0) @map("view_count")
  createdAt         DateTime    @default(now()) @map("created_at")
  updatedAt         DateTime    @updatedAt @map("updated_at")

  // Relations
  user              User        @relation(fields: [userId], references: [id], onDelete: Cascade)
  game              Game        @relation(fields: [gameId], references: [id], onDelete: Cascade)
  components        ReviewComponent?
  likes             Like[]
  comments          Comment[]
  reports           Report[]

  @@map("reviews")
}

model ReviewComponent {
  id                String   @id @default(cuid())
  reviewId          String   @unique @map("review_id")
  storyScore        Int      @map("story_score") @db.SmallInt
  characterScore    Int      @map("character_score") @db.SmallInt
  musicScore        Int      @map("music_score") @db.SmallInt
  controlsScore     Int      @map("controls_score") @db.SmallInt
  multiplayerScore  Int      @map("multiplayer_score") @db.SmallInt
  soloScore         Int      @map("solo_score") @db.SmallInt
  isAiGenerated     Boolean  @default(true) @map("is_ai_generated")
  aiConfidence      Float?   @map("ai_confidence")
  createdAt         DateTime @default(now()) @map("created_at")
  updatedAt         DateTime @updatedAt @map("updated_at")

  // Relations
  review            Review   @relation(fields: [reviewId], references: [id], onDelete: Cascade)

  @@map("review_components")
}

model Like {
  id        String   @id @default(cuid())
  userId    String   @map("user_id")
  reviewId  String   @map("review_id")
  createdAt DateTime @default(now()) @map("created_at")

  // Relations
  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  review    Review   @relation(fields: [reviewId], references: [id], onDelete: Cascade)

  @@unique([userId, reviewId])
  @@map("likes")
}

model Comment {
  id        String        @id @default(cuid())
  userId    String        @map("user_id")
  reviewId  String        @map("review_id")
  content   String
  status    CommentStatus @default(PENDING)
  createdAt DateTime      @default(now()) @map("created_at")
  updatedAt DateTime      @updatedAt @map("updated_at")

  // Relations
  user      User          @relation(fields: [userId], references: [id], onDelete: Cascade)
  review    Review        @relation(fields: [reviewId], references: [id], onDelete: Cascade)

  @@map("comments")
}

model Report {
  id          String       @id @default(cuid())
  reporterId  String       @map("reporter_id")
  reviewId    String       @map("review_id")
  reason      ReportReason
  description String?
  status      ReportStatus @default(PENDING)
  reviewedAt  DateTime?    @map("reviewed_at")
  reviewedBy  String?      @map("reviewed_by")
  createdAt   DateTime     @default(now()) @map("created_at")

  // Relations
  reporter    User         @relation("UserReports", fields: [reporterId], references: [id], onDelete: Cascade)
  review      Review       @relation(fields: [reviewId], references: [id], onDelete: Cascade)
  reviewer    User?        @relation("ReportedReviews", fields: [reviewedBy], references: [id])

  @@map("reports")
}

model LoginHistory {
  id        String   @id @default(cuid())
  userId    String   @map("user_id")
  ipAddress String   @map("ip_address")
  userAgent String   @map("user_agent")
  loginAt   DateTime @default(now()) @map("login_at")

  // Relations
  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("login_history")
}

// Enums
enum UserRole {
  USER
  MODERATOR
  ADMIN
}

enum ConsentStatus {
  PENDING
  APPROVED
  DENIED
}

enum ReviewStatus {
  PENDING
  APPROVED
  REJECTED
  FLAGGED
}

enum CommentStatus {
  PENDING
  APPROVED
  REJECTED
}

enum ReportReason {
  INAPPROPRIATE_CONTENT
  HARASSMENT
  SPAM
  COPYRIGHT
  OTHER
}

enum ReportStatus {
  PENDING
  REVIEWED
  RESOLVED
  DISMISSED
}
```

### 2.2. インデックス最適化

```sql
-- パフォーマンス向上のための追加インデックス
CREATE INDEX CONCURRENTLY idx_reviews_user_created 
ON reviews(user_id, created_at DESC);

CREATE INDEX CONCURRENTLY idx_reviews_game_status 
ON reviews(game_id, status) WHERE status = 'APPROVED';

CREATE INDEX CONCURRENTLY idx_reviews_status_created 
ON reviews(status, created_at DESC) WHERE status = 'APPROVED';

CREATE INDEX CONCURRENTLY idx_review_components_scores 
ON review_components(story_score, character_score, music_score, controls_score, multiplayer_score, solo_score);

CREATE INDEX CONCURRENTLY idx_likes_review_count 
ON likes(review_id);

CREATE INDEX CONCURRENTLY idx_users_consent_status 
ON users(parental_consent_status) WHERE is_parental_consent_required = true;

-- 全文検索用インデックス
CREATE INDEX CONCURRENTLY idx_games_title_search 
ON games USING gin(to_tsvector('japanese', title));

CREATE INDEX CONCURRENTLY idx_reviews_text_search 
ON reviews USING gin(to_tsvector('japanese', transcribed_text));
```

## 3. API詳細設計

### 3.1. OpenAPI仕様

```yaml
# docs/api-spec.yaml
openapi: 3.0.3
info:
  title: Game Review Service API
  version: 1.0.0
  description: 子供向けゲームレビューSNS API

paths:
  /api/v1/auth/register:
    post:
      summary: ユーザー登録
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - email
                - password
                - nickname
                - birthDate
              properties:
                email:
                  type: string
                  format: email
                  example: "user@example.com"
                password:
                  type: string
                  minLength: 8
                  example: "password123"
                nickname:
                  type: string
                  minLength: 2
                  maxLength: 50
                  example: "ゲーマー太郎"
                birthDate:
                  type: string
                  format: date
                  example: "2010-05-15"
      responses:
        '201':
          description: 登録成功
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AuthResponse'
        '400':
          description: バリデーションエラー
        '409':
          description: メールアドレス既存

  /api/v1/reviews:
    post:
      summary: レビュー作成
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              type: object
              required:
                - audioFile
                - gameId
                - audioDuration
              properties:
                audioFile:
                  type: string
                  format: binary
                gameId:
                  type: string
                  example: "game_123"
                audioDuration:
                  type: integer
                  minimum: 1
                  maximum: 180
                  example: 45
                playTimeHours:
                  type: integer
                  minimum: 0
                  example: 10
      responses:
        '201':
          description: レビュー作成成功
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Review'

    get:
      summary: レビュー一覧取得
      parameters:
        - name: page
          in: query
          schema:
            type: integer
            minimum: 1
            default: 1
        - name: limit
          in: query
          schema:
            type: integer
            minimum: 1
            maximum: 50
            default: 20
        - name: gameId
          in: query
          schema:
            type: string
        - name: sortBy
          in: query
          schema:
            type: string
            enum: [newest, oldest, popular, recommended]
            default: recommended
      responses:
        '200':
          description: レビュー一覧
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/PaginatedReviews'

components:
  schemas:
    User:
      type: object
      properties:
        id:
          type: string
        email:
          type: string
        nickname:
          type: string
        profileImageUrl:
          type: string
        isParentalConsentRequired:
          type: boolean
        parentalConsentStatus:
          type: string
          enum: [pending, approved, denied]

    Game:
      type: object
      properties:
        id:
          type: string
        title:
          type: string
        platform:
          type: string
        genre:
          type: string
        imageUrl:
          type: string

    Review:
      type: object
      properties:
        id:
          type: string
        user:
          $ref: '#/components/schemas/User'
        game:
          $ref: '#/components/schemas/Game'
        audioFileUrl:
          type: string
        audioDuration:
          type: integer
        highlightText:
          type: string
        playTimeHours:
          type: integer
        components:
          $ref: '#/components/schemas/ReviewComponent'
        likeCount:
          type: integer
        commentCount:
          type: integer
        isLikedByCurrentUser:
          type: boolean
        createdAt:
          type: string
          format: date-time

    ReviewComponent:
      type: object
      properties:
        storyScore:
          type: integer
          minimum: 0
          maximum: 10
        characterScore:
          type: integer
          minimum: 0
          maximum: 10
        musicScore:
          type: integer
          minimum: 0
          maximum: 10
        controlsScore:
          type: integer
          minimum: 0
          maximum: 10
        multiplayerScore:
          type: integer
          minimum: 0
          maximum: 10
        soloScore:
          type: integer
          minimum: 0
          maximum: 10
        isAiGenerated:
          type: boolean

  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
```

## 4. フロントエンド詳細設計

### 4.1. React Native コンポーネント設計

```typescript
// components/review/ReviewCard.tsx
interface ReviewCardProps {
  review: Review;
  onLike: (reviewId: string) => void;
  onComment: (reviewId: string) => void;
  onShare: (reviewId: string) => void;
  onPlayAudio: (audioUrl: string) => void;
}

export const ReviewCard: React.FC<ReviewCardProps> = ({
  review,
  onLike,
  onComment,
  onShare,
  onPlayAudio
}) => {
  const [isPlaying, setIsPlaying] = useState(false);
  const [audioProgress, setAudioProgress] = useState(0);

  return (
    <Animated.View style={styles.card}>
      {/* ゲーム画像 */}
      <View style={styles.gameImageContainer}>
        <Image 
          source={{ uri: review.game.imageUrl }} 
          style={styles.gameImage}
          resizeMode="cover"
        />
        <LinearGradient 
          colors={['transparent', 'rgba(0,0,0,0.7)']}
          style={styles.gradientOverlay}
        />
        <Text style={styles.gameTitle}>{review.game.title}</Text>
      </View>

      {/* 成分グラフ */}
      <View style={styles.componentsContainer}>
        <ComponentsRadarChart 
          components={review.components}
          size={120}
        />
      </View>

      {/* ユーザー情報 */}
      <View style={styles.userInfo}>
        <Avatar 
          source={{ uri: review.user.profileImageUrl }}
          size={32}
        />
        <Text style={styles.username}>{review.user.nickname}</Text>
        <Text style={styles.playTime}>
          プレイ時間: {review.playTimeHours}時間
        </Text>
      </View>

      {/* 音声プレイヤー */}
      <View style={styles.audioPlayer}>
        <TouchableOpacity 
          style={styles.playButton}
          onPress={() => onPlayAudio(review.audioFileUrl)}
        >
          <Icon 
            name={isPlaying ? 'pause' : 'play'} 
            size={24} 
            color="#fff" 
          />
        </TouchableOpacity>
        
        <View style={styles.waveformContainer}>
          <AudioWaveform 
            audioUrl={review.audioFileUrl}
            progress={audioProgress}
            duration={review.audioDuration}
          />
        </View>
        
        <Text style={styles.duration}>
          {formatDuration(review.audioDuration)}
        </Text>
      </View>

      {/* ハイライトテキスト */}
      <View style={styles.highlightContainer}>
        <Text style={styles.highlightText}>
          "{review.highlightText}"
        </Text>
      </View>

      {/* アクションボタン */}
      <View style={styles.actions}>
        <ActionButton
          icon="heart"
          count={review.likeCount}
          isActive={review.isLikedByCurrentUser}
          onPress={() => onLike(review.id)}
        />
        <ActionButton
          icon="comment"
          count={review.commentCount}
          onPress={() => onComment(review.id)}
        />
        <ActionButton
          icon="share"
          onPress={() => onShare(review.id)}
        />
      </View>
    </Animated.View>
  );
};

// コンポーネントスタイル
const styles = StyleSheet.create({
  card: {
    backgroundColor: '#fff',
    borderRadius: 16,
    marginHorizontal: 16,
    marginVertical: 8,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 8,
    elevation: 4,
  },
  gameImageContainer: {
    height: 200,
    borderTopLeftRadius: 16,
    borderTopRightRadius: 16,
    overflow: 'hidden',
    position: 'relative',
  },
  gameImage: {
    width: '100%',
    height: '100%',
  },
  gradientOverlay: {
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    height: 60,
  },
  gameTitle: {
    position: 'absolute',
    bottom: 12,
    left: 16,
    color: '#fff',
    fontSize: 18,
    fontWeight: 'bold',
  },
  componentsContainer: {
    padding: 16,
    alignItems: 'center',
  },
  userInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 16,
    paddingBottom: 12,
  },
  username: {
    marginLeft: 8,
    fontSize: 14,
    fontWeight: '600',
    flex: 1,
  },
  playTime: {
    fontSize: 12,
    color: '#666',
  },
  audioPlayer: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 16,
    paddingVertical: 12,
    backgroundColor: '#f8f9fa',
  },
  playButton: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#007AFF',
    justifyContent: 'center',
    alignItems: 'center',
  },
  waveformContainer: {
    flex: 1,
    marginHorizontal: 12,
    height: 40,
  },
  duration: {
    fontSize: 12,
    color: '#666',
    minWidth: 35,
    textAlign: 'right',
  },
  highlightContainer: {
    paddingHorizontal: 16,
    paddingVertical: 12,
  },
  highlightText: {
    fontSize: 14,
    fontStyle: 'italic',
    color: '#333',
    lineHeight: 20,
  },
  actions: {
    flexDirection: 'row',
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderTopWidth: 1,
    borderTopColor: '#f0f0f0',
  },
});
```

### 4.2. 状態管理設計 (Zustand)

```typescript
// store/authStore.ts
interface AuthState {
  user: User | null;
  tokens: {
    accessToken: string;
    refreshToken: string;
  } | null;
  isLoading: boolean;
  error: string | null;
}

interface AuthActions {
  login: (credentials: LoginRequest) => Promise<void>;
  register: (userData: RegisterRequest) => Promise<void>;
  logout: () => void;
  refreshToken: () => Promise<void>;
  clearError: () => void;
}

export const useAuthStore = create<AuthState & AuthActions>((set, get) => ({
  user: null,
  tokens: null,
  isLoading: false,
  error: null,

  login: async (credentials) => {
    set({ isLoading: true, error: null });
    try {
      const response = await authService.login(credentials);
      
      // トークンを安全なストレージに保存
      await SecureStore.setItemAsync('accessToken', response.tokens.accessToken);
      await SecureStore.setItemAsync('refreshToken', response.tokens.refreshToken);
      
      set({ 
        user: response.user, 
        tokens: response.tokens, 
        isLoading: false 
      });
    } catch (error) {
      set({ 
        error: error.message, 
        isLoading: false 
      });
    }
  },

  register: async (userData) => {
    set({ isLoading: true, error: null });
    try {
      const response = await authService.register(userData);
      
      if (response.user.isParentalConsentRequired && 
          response.user.parentalConsentStatus === 'pending') {
        // 保護者同意待ち状態
        set({ 
          user: response.user, 
          tokens: null, 
          isLoading: false 
        });
      } else {
        await SecureStore.setItemAsync('accessToken', response.tokens.accessToken);
        await SecureStore.setItemAsync('refreshToken', response.tokens.refreshToken);
        
        set({ 
          user: response.user, 
          tokens: response.tokens, 
          isLoading: false 
        });
      }
    } catch (error) {
      set({ 
        error: error.message, 
        isLoading: false 
      });
    }
  },

  logout: async () => {
    await SecureStore.deleteItemAsync('accessToken');
    await SecureStore.deleteItemAsync('refreshToken');
    set({ user: null, tokens: null, error: null });
  },

  refreshToken: async () => {
    const refreshToken = await SecureStore.getItemAsync('refreshToken');
    if (!refreshToken) {
      get().logout();
      return;
    }

    try {
      const response = await authService.refreshToken(refreshToken);
      await SecureStore.setItemAsync('accessToken', response.accessToken);
      set({ tokens: response });
    } catch (error) {
      get().logout();
    }
  },

  clearError: () => set({ error: null }),
}));

// store/reviewStore.ts
interface ReviewState {
  reviews: Review[];
  currentReviewIndex: number;
  isLoading: boolean;
  hasMore: boolean;
  error: string | null;
}

interface ReviewActions {
  loadReviews: (refresh?: boolean) => Promise<void>;
  nextReview: () => void;
  previousReview: () => void;
  likeReview: (reviewId: string) => Promise<void>;
  createReview: (data: CreateReviewRequest) => Promise<void>;
}

export const useReviewStore = create<ReviewState & ReviewActions>((set, get) => ({
  reviews: [],
  currentReviewIndex: 0,
  isLoading: false,
  hasMore: true,
  error: null,

  loadReviews: async (refresh = false) => {
    const state = get();
    if (state.isLoading) return;

    set({ isLoading: true, error: null });

    try {
      const page = refresh ? 1 : Math.floor(state.reviews.length / 20) + 1;
      const response = await reviewService.getReviews({ page, limit: 20 });

      set({
        reviews: refresh ? response.data : [...state.reviews, ...response.data],
        hasMore: response.data.length === 20,
        isLoading: false,
        currentReviewIndex: refresh ? 0 : state.currentReviewIndex
      });
    } catch (error) {
      set({ error: error.message, isLoading: false });
    }
  },

  nextReview: () => {
    const state = get();
    const nextIndex = state.currentReviewIndex + 1;
    
    if (nextIndex < state.reviews.length) {
      set({ currentReviewIndex: nextIndex });
    } else if (state.hasMore && !state.isLoading) {
      // 次のページを読み込み
      state.loadReviews();
    }
  },

  previousReview: () => {
    const state = get();
    if (state.currentReviewIndex > 0) {
      set({ currentReviewIndex: state.currentReviewIndex - 1 });
    }
  },

  likeReview: async (reviewId) => {
    try {
      await reviewService.likeReview(reviewId);
      
      const state = get();
      const updatedReviews = state.reviews.map(review => 
        review.id === reviewId 
          ? { 
              ...review, 
              isLikedByCurrentUser: !review.isLikedByCurrentUser,
              likeCount: review.isLikedByCurrentUser 
                ? review.likeCount - 1 
                : review.likeCount + 1
            }
          : review
      );
      
      set({ reviews: updatedReviews });
    } catch (error) {
      set({ error: error.message });
    }
  },

  createReview: async (data) => {
    set({ isLoading: true, error: null });
    try {
      const newReview = await reviewService.createReview(data);
      const state = get();
      set({ 
        reviews: [newReview, ...state.reviews],
        isLoading: false 
      });
    } catch (error) {
      set({ error: error.message, isLoading: false });
    }
  },
}));
```

## 5. テスト設計

### 5.1. ユニットテスト設計

```typescript
// tests/services/auth.service.test.ts
describe('AuthService', () => {
  let authService: AuthService;
  let mockUserRepository: jest.Mocked<UserRepository>;
  let mockEmailService: jest.Mocked<EmailService>;

  beforeEach(() => {
    mockUserRepository = createMockUserRepository();
    mockEmailService = createMockEmailService();
    authService = new AuthService(
      mockUserRepository,
      new JwtService({}),
      mockEmailService,
      new RedisService({})
    );
  });

  describe('register', () => {
    it('should create user with parental consent for users under 13', async () => {
      // Arrange
      const userData = {
        email: 'child@example.com',
        password: 'password123',
        nickname: '子供ユーザー',
        birthDate: '2015-01-01' // 10歳
      };

      mockUserRepository.create.mockResolvedValue({
        id: 'user123',
        ...userData,
        isParentalConsentRequired: true,
        parentalConsentStatus: 'pending'
      });

      // Act
      const result = await authService.register(userData);

      // Assert
      expect(result.user.isParentalConsentRequired).toBe(true);
      expect(result.user.parentalConsentStatus).toBe('pending');
      expect(mockEmailService.sendParentalConsentEmail).toHaveBeenCalled();
    });

    it('should create user without parental consent for users 13 and over', async () => {
      // Arrange
      const userData = {
        email: 'teen@example.com',
        password: 'password123',
        nickname: '中学生ユーザー',
        birthDate: '2008-01-01' // 17歳
      };

      mockUserRepository.create.mockResolvedValue({
        id: 'user123',
        ...userData,
        isParentalConsentRequired: false,
        parentalConsentStatus: 'approved'
      });

      // Act
      const result = await authService.register(userData);

      // Assert
      expect(result.user.isParentalConsentRequired).toBe(false);
      expect(result.tokens).toBeDefined();
      expect(mockEmailService.sendParentalConsentEmail).not.toHaveBeenCalled();
    });
  });
});

// tests/services/ai.service.test.ts
describe('AiService', () => {
  let aiService: AiService;
  let mockOpenAI: jest.Mocked<OpenAI>;

  beforeEach(() => {
    mockOpenAI = createMockOpenAI();
    aiService = new AiService(mockOpenAI, new ConfigService({}));
  });

  describe('generateComponents', () => {
    it('should generate valid component scores', async () => {
      // Arrange
      const transcribedText = 'このゲーム、ストーリーがとても面白くて、キャラクターも魅力的です！';
      const gameId = 'game123';

      mockOpenAI.chat.completions.create.mockResolvedValue({
        choices: [{
          message: {
            content: JSON.stringify({
              story: 9,
              character: 8,
              music: 6,
              controls: 7,
              multiplayer: 3,
              solo: 8
            })
          }
        }]
      });

      // Act
      const result = await aiService.generateComponents(transcribedText, gameId);

      // Assert
      expect(result.storyScore).toBe(9);
      expect(result.characterScore).toBe(8);
      expect(result.storyScore).toBeGreaterThanOrEqual(0);
      expect(result.storyScore).toBeLessThanOrEqual(10);
    });

    it('should return default components on API failure', async () => {
      // Arrange
      mockOpenAI.chat.completions.create.mockRejectedValue(new Error('API Error'));

      // Act
      const result = await aiService.generateComponents('test text', 'game123');

      // Assert
      expect(result).toEqual({
        storyScore: 5,
        characterScore: 5,
        musicScore: 5,
        controlsScore: 5,
        multiplayerScore: 5,
        soloScore: 5
      });
    });
  });
});
```

### 5.2. 統合テスト設計

```typescript
// tests/integration/review.e2e.test.ts
describe('Review API (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let accessToken: string;

  beforeAll(async () => {
    app = await createTestApp();
    prisma = app.get(PrismaService);
    
    // テストユーザー作成とログイン
    const authResponse = await request(app.getHttpServer())
      .post('/api/v1/auth/register')
      .send({
        email: 'test@example.com',
        password: 'password123',
        nickname: 'テストユーザー',
        birthDate: '2008-01-01'
      });
    
    accessToken = authResponse.body.tokens.accessToken;
  });

  describe('POST /api/v1/reviews', () => {
    it('should create review with audio file', async () => {
      // Arrange
      const audioBuffer = fs.readFileSync('./tests/fixtures/sample-audio.mp3');
      const gameId = await createTestGame();

      // Act
      const response = await request(app.getHttpServer())
        .post('/api/v1/reviews')
        .set('Authorization', `Bearer ${accessToken}`)
        .attach('audioFile', audioBuffer, 'test-audio.mp3')
        .field('gameId', gameId)
        .field('audioDuration', '45')
        .field('playTimeHours', '10');

      // Assert
      expect(response.status).toBe(201);
      expect(response.body.data.audioFileUrl).toBeDefined();
      expect(response.body.data.components).toBeDefined();
      expect(response.body.data.transcribedText).toBeDefined();
    });

    it('should reject oversized audio file', async () => {
      // Arrange
      const largeAudioBuffer = Buffer.alloc(11 * 1024 * 1024); // 11MB
      const gameId = await createTestGame();

      // Act
      const response = await request(app.getHttpServer())
        .post('/api/v1/reviews')
        .set('Authorization', `Bearer ${accessToken}`)
        .attach('audioFile', largeAudioBuffer, 'large-audio.mp3')
        .field('gameId', gameId)
        .field('audioDuration', '45');

      // Assert
      expect(response.status).toBe(400);
      expect(response.body.error.message).toContain('Audio file too large');
    });
  });

  describe('GET /api/v1/reviews', () => {
    it('should return paginated reviews', async () => {
      // Arrange
      await createTestReviews(25); // 25件のテストレビュー作成

      // Act
      const response = await request(app.getHttpServer())
        .get('/api/v1/reviews?page=1&limit=20')
        .set('Authorization', `Bearer ${accessToken}`);

      // Assert
      expect(response.status).toBe(200);
      expect(response.body.data).toHaveLength(20);
      expect(response.body.meta.total).toBe(25);
      expect(response.body.meta.page).toBe(1);
    });

    it('should filter by game ID', async () => {
      // Arrange
      const gameId = await createTestGame();
      await createTestReviewsForGame(gameId, 5);

      // Act
      const response = await request(app.getHttpServer())
        .get(`/api/v1/reviews?gameId=${gameId}`)
        .set('Authorization', `Bearer ${accessToken}`);

      // Assert
      expect(response.status).toBe(200);
      expect(response.body.data).toHaveLength(5);
      response.body.data.forEach(review => {
        expect(review.game.id).toBe(gameId);
      });
    });
  });

  afterAll(async () => {
    await cleanupTestData();
    await app.close();
  });
});
```

---

**レビュー・承認:**
- テックリード: ___________
- 品質保証: ___________
- プロダクトオーナー: ___________

**更新履歴:**
- v1.0: 初版作成（全モジュール詳細設計完了）