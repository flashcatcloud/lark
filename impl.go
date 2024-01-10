// Code generated by lark_sdk_gen. DO NOT EDIT.
/**
 * Copyright 2022 chyroc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package lark

import (
	"context"
	"time"
)

// Lark client struct
type Lark struct {
	appID               string
	appSecret           string
	encryptKey          string
	verificationToken   string
	helpdeskID          string
	helpdeskToken       string
	timeout             time.Duration
	isISV               bool
	tenantKey           string
	customBotWebHookURL string
	customBotSecret     string
	openBaseURL         string
	wwwBaseURL          string
	isEnableLogID       bool
	noBlocking          bool
	apiMiddlewares      []ApiMiddleware

	httpClient       HttpClient
	logger           Logger
	logLevel         LogLevel
	store            Store
	mock             *Mock
	eventHandler     *eventHandler
	getAppTicketFunc func(ctx context.Context, larkClient *Lark, appID string) (string, error)
	wrapDoRequest    ApiEndpoint

	// service
	ACS              *ACSService
	AI               *AIService
	Admin            *AdminService
	AppLink          *AppLinkService
	Application      *ApplicationService
	Approval         *ApprovalService
	Attendance       *AttendanceService
	Auth             *AuthService
	Baike            *BaikeService
	Bitable          *BitableService
	Bot              *BotService
	Calendar         *CalendarService
	Chat             *ChatService
	Contact          *ContactService
	CoreHR           *CoreHRService
	Drive            *DriveService
	EHR              *EHRService
	Event            *EventService
	EventCallback    *EventCallbackService
	File             *FileService
	Helpdesk         *HelpdeskService
	Hire             *HireService
	HumanAuth        *HumanAuthService
	Jssdk            *JssdkService
	Lingo            *LingoService
	Mail             *MailService
	Message          *MessageService
	Mina             *MinaService
	Minutes          *MinutesService
	OKR              *OKRService
	Passport         *PassportService
	Performance      *PerformanceService
	PersonalSettings *PersonalSettingsService
	Search           *SearchService
	Task             *TaskService
	Tenant           *TenantService
	VC               *VCService
	Verification     *VerificationService
}

func (r *Lark) AppID() string {
	return r.appID
}

func (r *Lark) AppSecret() string {
	return r.appSecret
}

func (r *Lark) init() {
	r.wrapDoRequest = chainApiMiddleware(r.apiMiddlewares...)(r.rawRequest)

	r.ACS = &ACSService{cli: r}
	r.AI = &AIService{cli: r}
	r.Admin = &AdminService{cli: r}
	r.AppLink = &AppLinkService{cli: r}
	r.Application = &ApplicationService{cli: r}
	r.Approval = &ApprovalService{cli: r}
	r.Attendance = &AttendanceService{cli: r}
	r.Auth = &AuthService{cli: r}
	r.Baike = &BaikeService{cli: r}
	r.Bitable = &BitableService{cli: r}
	r.Bot = &BotService{cli: r}
	r.Calendar = &CalendarService{cli: r}
	r.Chat = &ChatService{cli: r}
	r.Contact = &ContactService{cli: r}
	r.CoreHR = &CoreHRService{cli: r}
	r.Drive = &DriveService{cli: r}
	r.EHR = &EHRService{cli: r}
	r.Event = &EventService{cli: r}
	r.EventCallback = &EventCallbackService{cli: r}
	r.File = &FileService{cli: r}
	r.Helpdesk = &HelpdeskService{cli: r}
	r.Hire = &HireService{cli: r}
	r.HumanAuth = &HumanAuthService{cli: r}
	r.Jssdk = &JssdkService{cli: r}
	r.Lingo = &LingoService{cli: r}
	r.Mail = &MailService{cli: r}
	r.Message = &MessageService{cli: r}
	r.Mina = &MinaService{cli: r}
	r.Minutes = &MinutesService{cli: r}
	r.OKR = &OKRService{cli: r}
	r.Passport = &PassportService{cli: r}
	r.Performance = &PerformanceService{cli: r}
	r.PersonalSettings = &PersonalSettingsService{cli: r}
	r.Search = &SearchService{cli: r}
	r.Task = &TaskService{cli: r}
	r.Tenant = &TenantService{cli: r}
	r.VC = &VCService{cli: r}
	r.Verification = &VerificationService{cli: r}

}

func (r *Lark) clone(tenantKey string) *Lark {
	r2 := &Lark{
		appID:               r.appID,
		appSecret:           r.appSecret,
		encryptKey:          r.encryptKey,
		verificationToken:   r.verificationToken,
		helpdeskID:          r.helpdeskID,
		helpdeskToken:       r.helpdeskToken,
		timeout:             r.timeout,
		isISV:               r.isISV,
		tenantKey:           tenantKey,
		customBotWebHookURL: r.customBotWebHookURL,
		customBotSecret:     r.customBotSecret,
		openBaseURL:         r.openBaseURL,
		wwwBaseURL:          r.wwwBaseURL,
		isEnableLogID:       r.isEnableLogID,
		noBlocking:          r.noBlocking,
		httpClient:          r.httpClient,
		logger:              r.logger,
		logLevel:            r.logLevel,
		store:               r.store,
		mock:                r.mock,
		eventHandler:        r.eventHandler,
		getAppTicketFunc:    r.getAppTicketFunc,
		apiMiddlewares:      r.apiMiddlewares,
		wrapDoRequest:       r.wrapDoRequest,
	}
	r2.init()
	return r2
}

type ACSService struct{ cli *Lark }
type AIService struct{ cli *Lark }
type AdminService struct{ cli *Lark }
type AppLinkService struct{ cli *Lark }
type ApplicationService struct{ cli *Lark }
type ApprovalService struct{ cli *Lark }
type AttendanceService struct{ cli *Lark }
type AuthService struct{ cli *Lark }
type BaikeService struct{ cli *Lark }
type BitableService struct{ cli *Lark }
type BotService struct{ cli *Lark }
type CalendarService struct{ cli *Lark }
type ChatService struct{ cli *Lark }
type ContactService struct{ cli *Lark }
type CoreHRService struct{ cli *Lark }
type DriveService struct{ cli *Lark }
type EHRService struct{ cli *Lark }
type EventService struct{ cli *Lark }
type EventCallbackService struct{ cli *Lark }
type FileService struct{ cli *Lark }
type HelpdeskService struct{ cli *Lark }
type HireService struct{ cli *Lark }
type HumanAuthService struct{ cli *Lark }
type JssdkService struct{ cli *Lark }
type LingoService struct{ cli *Lark }
type MailService struct{ cli *Lark }
type MessageService struct{ cli *Lark }
type MinaService struct{ cli *Lark }
type MinutesService struct{ cli *Lark }
type OKRService struct{ cli *Lark }
type PassportService struct{ cli *Lark }
type PerformanceService struct{ cli *Lark }
type PersonalSettingsService struct{ cli *Lark }
type SearchService struct{ cli *Lark }
type TaskService struct{ cli *Lark }
type TenantService struct{ cli *Lark }
type VCService struct{ cli *Lark }
type VerificationService struct{ cli *Lark }
