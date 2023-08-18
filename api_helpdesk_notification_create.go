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
)

// CreateHelpdeskNotification 调用接口创建推送, 创建成功后为草稿状态。
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/helpdesk-v1/notification/create
// new doc: https://open.feishu.cn/document/server-docs/helpdesk-v1/notification/create
func (r *HelpdeskService) CreateHelpdeskNotification(ctx context.Context, request *CreateHelpdeskNotificationReq, options ...MethodOptionFunc) (*CreateHelpdeskNotificationResp, *Response, error) {
	if r.cli.mock.mockHelpdeskCreateHelpdeskNotification != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Helpdesk#CreateHelpdeskNotification mock enable")
		return r.cli.mock.mockHelpdeskCreateHelpdeskNotification(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:               "Helpdesk",
		API:                 "CreateHelpdeskNotification",
		Method:              "POST",
		URL:                 r.cli.openBaseURL + "/open-apis/helpdesk/v1/notifications",
		Body:                request,
		MethodOption:        newMethodOption(options),
		NeedUserAccessToken: true,
		NeedHelpdeskAuth:    true,
	}
	resp := new(createHelpdeskNotificationResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

// MockHelpdeskCreateHelpdeskNotification mock HelpdeskCreateHelpdeskNotification method
func (r *Mock) MockHelpdeskCreateHelpdeskNotification(f func(ctx context.Context, request *CreateHelpdeskNotificationReq, options ...MethodOptionFunc) (*CreateHelpdeskNotificationResp, *Response, error)) {
	r.mockHelpdeskCreateHelpdeskNotification = f
}

// UnMockHelpdeskCreateHelpdeskNotification un-mock HelpdeskCreateHelpdeskNotification method
func (r *Mock) UnMockHelpdeskCreateHelpdeskNotification() {
	r.mockHelpdeskCreateHelpdeskNotification = nil
}

// CreateHelpdeskNotificationReq ...
type CreateHelpdeskNotificationReq struct {
	UserIDType                  *IDType                                                 `query:"user_id_type" json:"-"`                    // 用户 ID 类型, 示例值: open_id, 可选值有: open_id: 标识一个用户在某个应用中的身份。同一个用户在不同应用中的 Open ID 不同。[了解更多: 如何获取 Open ID](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-openid), union_id: 标识一个用户在某个应用开发商下的身份。同一用户在同一开发商下的应用中的 Union ID 是相同的, 在不同开发商下的应用中的 Union ID 是不同的。通过 Union ID, 应用开发商可以把同个用户在多个应用中的身份关联起来。[了解更多: 如何获取 Union ID？](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-union-id), user_id: 标识一个用户在某个租户内的身份。同一个用户在租户 A 和租户 B 内的 User ID 是不同的。在同一个租户内, 一个用户的 User ID 在所有应用（包括商店应用）中都保持一致。User ID 主要用于在不同的应用间打通用户数据。[了解更多: 如何获取 User ID？](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-user-id), 默认值: `open_id`, 当值为 `user_id`, 字段权限要求: 获取用户 user ID
	ID                          *string                                                 `json:"id,omitempty"`                              // 非必填, 创建成功后返回, 示例值: "6981801914270744596"
	JobName                     *string                                                 `json:"job_name,omitempty"`                        // 必填, 任务名称, 示例值: "测试推送任务"
	Status                      *int64                                                  `json:"status,omitempty"`                          // 非必填, 创建成功后返回, 示例值: 0
	CreateUser                  *CreateHelpdeskNotificationReqCreateUser                `json:"create_user,omitempty"`                     // 非必填, 创建人, 示例值: {"avatar_url":"", "name":"", "user_id":"ou_7277fd1262bfafc363d5b2a1f9c2ac90"}
	CreatedAt                   *string                                                 `json:"created_at,omitempty"`                      // 非必填, 创建时间（毫秒时间戳）, 示例值: "1626332244719"
	UpdateUser                  *CreateHelpdeskNotificationReqUpdateUser                `json:"update_user,omitempty"`                     // 非必填, 更新用户, 示例值: {"avatar_url":"", "name":"", "user_id":"ou_7277fd1262bfafc363d5b2a1f9c2ac90"}
	UpdatedAt                   *string                                                 `json:"updated_at,omitempty"`                      // 非必填, 更新时间（毫秒时间戳）, 示例值: "1626332244719"
	TargetUserCount             *int64                                                  `json:"target_user_count,omitempty"`               // 非必填, 目标推送用户总数, 示例值: 1
	SentUserCount               *int64                                                  `json:"sent_user_count,omitempty"`                 // 非必填, 已推送用户总数, 示例值: 1
	ReadUserCount               *int64                                                  `json:"read_user_count,omitempty"`                 // 非必填, 已读用户总数, 示例值: 1
	SendAt                      *string                                                 `json:"send_at,omitempty"`                         // 非必填, 推送任务触发时间（毫秒时间戳）, 示例值: "1626332244719"
	PushContent                 *string                                                 `json:"push_content,omitempty"`                    // 必填, 推送内容, 详见: https://open.feishu.cn/tool/cardbuilder?from=howtoguide, 示例值: "{   \"config\": {     \"wide_screen_mode\": true   }, \"elements\": [     {       \"tag\": \"div\", \"text\": {         \"tag\": \"lark_md\", \"content\": \"[飞书](https://www.feishu.cn)整合即时沟通、日历、音视频会议、云文档、云盘、工作台等功能于一体, 成就组织和个人, 更高效、更愉悦。\"       }     }   ] }"
	PushType                    *int64                                                  `json:"push_type,omitempty"`                       // 必填, 0（定时推送: push_scope不能等于3） 1（新人入职推送: push_scope必须等于1或者3；new_staff_scope_type不能为空）, 示例值: 0
	PushScopeType               *int64                                                  `json:"push_scope_type,omitempty"`                 // 必填, 推送范围（服务台私信） 0: 组织内全部成员（user_list和department_list必须为空） 1: 不推送任何成员（user_list和department_list必须为空, chat_list不可为空） 2: 推送到部分成员（user_list或department_list不能为空） 3: 入职新人 以上四种状态, chat_list都相对独立, 只有在推送范围为1时, 必须需要设置chat_list, 示例值: 0
	NewStaffScopeType           *int64                                                  `json:"new_staff_scope_type,omitempty"`            // 非必填, 新人入职范围类型（push_type为1时生效） 0: 组织内所有新人 1: 组织内特定的部门（new_staff_scope_department_list 字段不能为空）, 示例值: 0
	NewStaffScopeDepartmentList []*CreateHelpdeskNotificationReqNewStaffScopeDepartment `json:"new_staff_scope_department_list,omitempty"` // 非必填, 新人入职生效部门列表, 示例值: [{"department_id":"od_7c1a2815c9846b5e518b950de0e62de8"}]
	UserList                    []*CreateHelpdeskNotificationReqUser                    `json:"user_list,omitempty"`                       // 非必填, push推送到成员列表, 示例值: [{"user_id":"ou_7277fd1262bfafc363d5b2a1f9c2ac90"}]
	DepartmentList              []*CreateHelpdeskNotificationReqDepartment              `json:"department_list,omitempty"`                 // 非必填, push推送到的部门信息列表, 示例值: [{"department_id":"od_7c1a2815c9846b5e518b950de0e62de8"}]
	ChatList                    []*CreateHelpdeskNotificationReqChat                    `json:"chat_list,omitempty"`                       // 非必填, push推送到的会话列表(群), 示例值: [{"chat_id":"oc_7c1a2815c9846b5e518b950de0e62de8"}]
	Ext                         *string                                                 `json:"ext,omitempty"`                             // 非必填, 预留扩展字段, 示例值: "{}"
}

// CreateHelpdeskNotificationReqChat ...
type CreateHelpdeskNotificationReqChat struct {
	ChatID *string `json:"chat_id,omitempty"` // 非必填, 会话ID, 示例值: "oc_7277fd1262bfafc363d5b2a1f9c2ac90"
	Name   *string `json:"name,omitempty"`    // 非必填, 会话名称, 示例值: "测试群聊"
}

// CreateHelpdeskNotificationReqCreateUser ...
type CreateHelpdeskNotificationReqCreateUser struct {
	UserID    *string `json:"user_id,omitempty"`    // 非必填, 用户id, 示例值: "ou_7277fd1262bfafc363d5b2a1f9c2ac90"
	AvatarURL *string `json:"avatar_url,omitempty"` // 非必填, 头像地址, 示例值: "http://*.com/*.png"
	Name      *string `json:"name,omitempty"`       // 非必填, 用户名称, 示例值: "test"
}

// CreateHelpdeskNotificationReqDepartment ...
type CreateHelpdeskNotificationReqDepartment struct {
	DepartmentID *string `json:"department_id,omitempty"` // 部门ID, 示例值: "od_7277fd1262bfafc363d5b2a1f9c2ac90"
	Name         *string `json:"name,omitempty"`          // 非必填, 部门名称, 示例值: "测试部门"
}

// CreateHelpdeskNotificationReqNewStaffScopeDepartment ...
type CreateHelpdeskNotificationReqNewStaffScopeDepartment struct {
	DepartmentID *string `json:"department_id,omitempty"` // 部门ID, 示例值: "od_7277fd1262bfafc363d5b2a1f9c2ac90"
	Name         *string `json:"name,omitempty"`          // 非必填, 部门名称, 示例值: "测试部门"
}

// CreateHelpdeskNotificationReqUpdateUser ...
type CreateHelpdeskNotificationReqUpdateUser struct {
	UserID    *string `json:"user_id,omitempty"`    // 非必填, 用户id, 示例值: "ou_7277fd1262bfafc363d5b2a1f9c2ac90"
	AvatarURL *string `json:"avatar_url,omitempty"` // 非必填, 头像地址, 示例值: "http://*.com/*.png"
	Name      *string `json:"name,omitempty"`       // 非必填, 用户名称, 示例值: "test"
}

// CreateHelpdeskNotificationReqUser ...
type CreateHelpdeskNotificationReqUser struct {
	UserID    *string `json:"user_id,omitempty"`    // 非必填, 用户id, 示例值: "ou_7277fd1262bfafc363d5b2a1f9c2ac90"
	AvatarURL *string `json:"avatar_url,omitempty"` // 非必填, 头像地址, 示例值: "http://*.com/*.png"
	Name      *string `json:"name,omitempty"`       // 非必填, 用户名称, 示例值: "test"
}

// CreateHelpdeskNotificationResp ...
type CreateHelpdeskNotificationResp struct {
	NotificationID string `json:"notification_id,omitempty"` // 创建成功后的唯一id
	Status         int64  `json:"status,omitempty"`          // 当前状态
}

// createHelpdeskNotificationResp ...
type createHelpdeskNotificationResp struct {
	Code int64                           `json:"code,omitempty"` // 错误码, 非 0 表示失败
	Msg  string                          `json:"msg,omitempty"`  // 错误描述
	Data *CreateHelpdeskNotificationResp `json:"data,omitempty"`
}
