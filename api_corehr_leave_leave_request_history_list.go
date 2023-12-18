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

// GetCoreHRLeaveRequestHistoryList 批量获取员工的请假记录数据。
//
// 仅飞书人事企业版可用
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/corehr-v1/leave/leave_request_history
// new doc: https://open.feishu.cn/document/server-docs/corehr-v1/leave/leave_request_history
func (r *CoreHRService) GetCoreHRLeaveRequestHistoryList(ctx context.Context, request *GetCoreHRLeaveRequestHistoryListReq, options ...MethodOptionFunc) (*GetCoreHRLeaveRequestHistoryListResp, *Response, error) {
	if r.cli.mock.mockCoreHRGetCoreHRLeaveRequestHistoryList != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] CoreHR#GetCoreHRLeaveRequestHistoryList mock enable")
		return r.cli.mock.mockCoreHRGetCoreHRLeaveRequestHistoryList(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "CoreHR",
		API:                   "GetCoreHRLeaveRequestHistoryList",
		Method:                "GET",
		URL:                   r.cli.openBaseURL + "/open-apis/corehr/v1/leaves/leave_request_history",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(getCoreHRLeaveRequestHistoryListResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

// MockCoreHRGetCoreHRLeaveRequestHistoryList mock CoreHRGetCoreHRLeaveRequestHistoryList method
func (r *Mock) MockCoreHRGetCoreHRLeaveRequestHistoryList(f func(ctx context.Context, request *GetCoreHRLeaveRequestHistoryListReq, options ...MethodOptionFunc) (*GetCoreHRLeaveRequestHistoryListResp, *Response, error)) {
	r.mockCoreHRGetCoreHRLeaveRequestHistoryList = f
}

// UnMockCoreHRGetCoreHRLeaveRequestHistoryList un-mock CoreHRGetCoreHRLeaveRequestHistoryList method
func (r *Mock) UnMockCoreHRGetCoreHRLeaveRequestHistoryList() {
	r.mockCoreHRGetCoreHRLeaveRequestHistoryList = nil
}

// GetCoreHRLeaveRequestHistoryListReq ...
type GetCoreHRLeaveRequestHistoryListReq struct {
	PageToken          *string  `query:"page_token" json:"-"`            // 分页标记, 第一次请求不填, 表示从头开始遍历；分页查询结果还有更多项时会同时返回新的 page_token, 下次遍历可采用该 page_token 获取查询结果, 示例值: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
	PageSize           int64    `query:"page_size" json:"-"`             // 分页大小, 示例值: 100
	EmploymentIDList   []string `query:"employment_id_list" json:"-"`    // 员工 ID 列表, 最大 100 个（不传则默认查询全部员工）, 示例值: 6919733291281024522
	InitiatorIDList    []string `query:"initiator_id_list" json:"-"`     // 休假发起人 ID 列表, 最大 100 个, 示例值: 6919733291281024523
	LeaveRequestStatus []string `query:"leave_request_status" json:"-"`  // 请假记录的状态, 可选值有: 1: 已通过, 2: 审批中, 3: 审批中（更正）, 4: 审批中（取消休假）, 5: 审批中（返岗）, 6: 已返岗, 7: 已拒绝, 8: 已取消, 9: 已撤回, 示例值: 1
	LeaveTypeIDList    []string `query:"leave_type_id_list" json:"-"`    // 假期类型 ID 列表, 枚举值可通过【获取假期类型列表】接口获取, 示例值: 4718803945687580501
	LeaveStartDateMin  *string  `query:"leave_start_date_min" json:"-"`  // 休假开始时间晚于等于的日期, 示例值: 2022-07-20
	LeaveStartDateMax  *string  `query:"leave_start_date_max" json:"-"`  // 休假开始时间早于等于的日期, 示例值: 2022-07-20
	LeaveEndDateMin    *string  `query:"leave_end_date_min" json:"-"`    // 休假结束时间晚于等于的日期, 示例值: 2022-07-20
	LeaveEndDateMax    *string  `query:"leave_end_date_max" json:"-"`    // 休假结束时间早于等于的日期, 示例值: 2022-07-20
	LeaveSubmitDateMin *string  `query:"leave_submit_date_min" json:"-"` // 休假发起时间晚于等于的日期, 示例值: 2022-07-20
	LeaveSubmitDateMax *string  `query:"leave_submit_date_max" json:"-"` // 休假发起时间早于等于的日期, 示例值: 2022-07-20
	UserIDType         *IDType  `query:"user_id_type" json:"-"`          // 用户 ID 类型, 示例值: people_corehr_id, 可选值有: open_id: 标识一个用户在某个应用中的身份。同一个用户在不同应用中的 Open ID 不同。[了解更多: 如何获取 Open ID](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-openid), union_id: 标识一个用户在某个应用开发商下的身份。同一用户在同一开发商下的应用中的 Union ID 是相同的, 在不同开发商下的应用中的 Union ID 是不同的。通过 Union ID, 应用开发商可以把同个用户在多个应用中的身份关联起来。[了解更多: 如何获取 Union ID？](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-union-id), user_id: 标识一个用户在某个租户内的身份。同一个用户在租户 A 和租户 B 内的 User ID 是不同的。在同一个租户内, 一个用户的 User ID 在所有应用（包括商店应用）中都保持一致。User ID 主要用于在不同的应用间打通用户数据。[了解更多: 如何获取 User ID？](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-user-id), people_corehr_id: 以飞书人事的 ID 来识别用户, 默认值: `people_corehr_id`, 当值为 `user_id`, 字段权限要求: 获取用户 user ID
	LeaveUpdateTimeMin *string  `query:"leave_update_time_min" json:"-"` // 请假记录更新时间晚于等于的时间, 示例值: 2022-10-24 10:00:00
	LeaveUpdateTimeMax *string  `query:"leave_update_time_max" json:"-"` // 请假记录更新时间早于等于的时间, 示例值: 2022-10-24 10:00:00
}

// GetCoreHRLeaveRequestHistoryListResp ...
type GetCoreHRLeaveRequestHistoryListResp struct {
	LeaveRequestList []*GetCoreHRLeaveRequestHistoryListRespLeaveRequest `json:"leave_request_list,omitempty"` // 请假记录信息列表
	HasMore          bool                                                `json:"has_more,omitempty"`           // 是否还有更多项
	PageToken        string                                              `json:"page_token,omitempty"`         // 分页标记, 当 has_more 为 true 时, 会同时返回新的 page_token, 否则不返回 page_token
}

// GetCoreHRLeaveRequestHistoryListRespLeaveRequest ...
type GetCoreHRLeaveRequestHistoryListRespLeaveRequest struct {
	LeaveRequestID     string                                                            `json:"leave_request_id,omitempty"`     // 请假记录ID
	EmploymentID       string                                                            `json:"employment_id,omitempty"`        // 雇佣信息ID
	EmploymentName     []*GetCoreHRLeaveRequestHistoryListRespLeaveRequestEmploymentName `json:"employment_name,omitempty"`      // 员工姓名
	LeaveTypeID        string                                                            `json:"leave_type_id,omitempty"`        // 假期类型ID
	LeaveTypeName      []*GetCoreHRLeaveRequestHistoryListRespLeaveRequestLeaveTypeName  `json:"leave_type_name,omitempty"`      // 假期类型名称
	StartTime          string                                                            `json:"start_time,omitempty"`           // 假期开始时间, 格式可能为: 字符串日期: 如 "2022-09-09", 字符串日期加 morning/afternoon: 如 "2022-09-09 morning""
	EndTime            string                                                            `json:"end_time,omitempty"`             // 假期结束时间, 格式可能为: 字符串日期: 如 "2022-09-09", 字符串日期加 morning/afternoon: 如 "2022-09-09 morning""
	LeaveDuration      string                                                            `json:"leave_duration,omitempty"`       // 假期时长
	LeaveDurationUnit  int64                                                             `json:"leave_duration_unit,omitempty"`  // 假期时长单位, 可选值有: 1: 天, 2: 小时
	LeaveRequestStatus int64                                                             `json:"leave_request_status,omitempty"` // 请假记录的状态, 可选值有: 1: 已通过, 2: 审批中, 3: 审批中（更正）, 4: 审批中（取消休假）, 5: 审批中（返岗）, 6: 已返岗, 7: 已拒绝, 8: 已取消, 9: 已撤回
	GrantSource        string                                                            `json:"grant_source,omitempty"`         // 数据来源, 可选值有: "manual": 手动创建, "system": 系统创建"
	ReturnTime         string                                                            `json:"return_time,omitempty"`          // 返岗时间
	SubmittedAt        string                                                            `json:"submitted_at,omitempty"`         // 发起时间
	SubmittedBy        string                                                            `json:"submitted_by,omitempty"`         // 发起人
	Notes              string                                                            `json:"notes,omitempty"`                // 备注
}

// GetCoreHRLeaveRequestHistoryListRespLeaveRequestEmploymentName ...
type GetCoreHRLeaveRequestHistoryListRespLeaveRequestEmploymentName struct {
	Lang  string `json:"lang,omitempty"`  // 名称信息的语言
	Value string `json:"value,omitempty"` // 名称信息的内容
}

// GetCoreHRLeaveRequestHistoryListRespLeaveRequestLeaveTypeName ...
type GetCoreHRLeaveRequestHistoryListRespLeaveRequestLeaveTypeName struct {
	Lang  string `json:"lang,omitempty"`  // 名称信息的语言
	Value string `json:"value,omitempty"` // 名称信息的内容
}

// getCoreHRLeaveRequestHistoryListResp ...
type getCoreHRLeaveRequestHistoryListResp struct {
	Code int64                                 `json:"code,omitempty"` // 错误码, 非 0 表示失败
	Msg  string                                `json:"msg,omitempty"`  // 错误描述
	Data *GetCoreHRLeaveRequestHistoryListResp `json:"data,omitempty"`
}
