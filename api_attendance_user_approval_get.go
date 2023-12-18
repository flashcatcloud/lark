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

// GetAttendanceUserApproval 获取员工在某段时间内的请假、加班、外出和出差四种审批的通过数据。
//
// 请假的假期时长字段, 暂未开放提供, 待后续提供。
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/attendance-v1/user_approval/query
// new doc: https://open.feishu.cn/document/server-docs/attendance-v1/user_approval/query
func (r *AttendanceService) GetAttendanceUserApproval(ctx context.Context, request *GetAttendanceUserApprovalReq, options ...MethodOptionFunc) (*GetAttendanceUserApprovalResp, *Response, error) {
	if r.cli.mock.mockAttendanceGetAttendanceUserApproval != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Attendance#GetAttendanceUserApproval mock enable")
		return r.cli.mock.mockAttendanceGetAttendanceUserApproval(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Attendance",
		API:                   "GetAttendanceUserApproval",
		Method:                "POST",
		URL:                   r.cli.openBaseURL + "/open-apis/attendance/v1/user_approvals/query",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(getAttendanceUserApprovalResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

// MockAttendanceGetAttendanceUserApproval mock AttendanceGetAttendanceUserApproval method
func (r *Mock) MockAttendanceGetAttendanceUserApproval(f func(ctx context.Context, request *GetAttendanceUserApprovalReq, options ...MethodOptionFunc) (*GetAttendanceUserApprovalResp, *Response, error)) {
	r.mockAttendanceGetAttendanceUserApproval = f
}

// UnMockAttendanceGetAttendanceUserApproval un-mock AttendanceGetAttendanceUserApproval method
func (r *Mock) UnMockAttendanceGetAttendanceUserApproval() {
	r.mockAttendanceGetAttendanceUserApproval = nil
}

// GetAttendanceUserApprovalReq ...
type GetAttendanceUserApprovalReq struct {
	EmployeeType  EmployeeType `query:"employee_type" json:"-"`   // 请求体中的 user_ids 和响应体中的 user_id 的员工工号类型, 示例值: employee_id, 可选值有: employee_id: 员工 employee ID, 即[飞书管理后台](https://example.feishu.cn/admin/index) > 组织架构 > 成员与部门 > 成员详情中的用户 ID, employee_no: 员工工号, 即[飞书管理后台](https://example.feishu.cn/admin/index) > 组织架构 > 成员与部门 > 成员详情中的工号
	UserIDs       []string     `json:"user_ids,omitempty"`        // employee_no 或 employee_id 列表, 示例值: ["abd754f7"]
	CheckDateFrom int64        `json:"check_date_from,omitempty"` // 查询的起始工作日, 示例值: 20190817
	CheckDateTo   int64        `json:"check_date_to,omitempty"`   // 查询的结束工作日, 与 check_date_from 的时间间隔不超过 30 天, 示例值: 20190820
	CheckDateType *string      `json:"check_date_type,omitempty"` // 查询依据的时间类型（不填默认依据PeriodTime）, 示例值: "PeriodTime", 可选值有: PeriodTime: 单据作用时间, CreateTime: 单据创建时间（目前暂不支持）, UpdateTime: 单据状态更新时间（新增字段, 对特定租户生效）
	Status        *int64       `json:"status,omitempty"`          // 查询状态（不填默认查询已通过状态）, 示例值: 2, 可选值有: 0: 待审批, 1: 未通过, 2: 已通过, 3: 已取消, 4: 已撤回
	CheckTimeFrom *string      `json:"check_time_from,omitempty"` // 查询的起始时间, 精确到秒的时间戳（灰度中, 暂不开放）, 示例值: "1566641088"
	CheckTimeTo   *string      `json:"check_time_to,omitempty"`   // 查询的结束时间, 精确到秒的时间戳（灰度中, 暂不开放）, 示例值: "1592561088"
}

// GetAttendanceUserApprovalResp ...
type GetAttendanceUserApprovalResp struct {
	UserApprovals []*GetAttendanceUserApprovalRespUserApproval `json:"user_approvals,omitempty"` // 审批结果列表
}

// GetAttendanceUserApprovalRespUserApproval ...
type GetAttendanceUserApprovalRespUserApproval struct {
	UserID        string                                                   `json:"user_id,omitempty"`        // 审批用户 ID
	Date          string                                                   `json:"date,omitempty"`           // 审批作用日期
	Outs          []*GetAttendanceUserApprovalRespUserApprovalOut          `json:"outs,omitempty"`           // 外出信息
	Leaves        []*GetAttendanceUserApprovalRespUserApprovalLeave        `json:"leaves,omitempty"`         // 请假信息
	OvertimeWorks []*GetAttendanceUserApprovalRespUserApprovalOvertimeWork `json:"overtime_works,omitempty"` // 加班信息
	Trips         []*GetAttendanceUserApprovalRespUserApprovalTrip         `json:"trips,omitempty"`          // 出差信息
	TimeZone      string                                                   `json:"time_zone,omitempty"`      // 计算时间所用的时区信息, 为空是0时区
}

// GetAttendanceUserApprovalRespUserApprovalLeave ...
type GetAttendanceUserApprovalRespUserApprovalLeave struct {
	ApprovalID       string     `json:"approval_id,omitempty"`        // 审批实例 ID
	UniqID           string     `json:"uniq_id,omitempty"`            // 假期类型唯一 ID, 代表一种假期类型, 长度小于 14, * 此ID对应假期类型(即: i18n_names), 因此需要保证唯一
	Unit             int64      `json:"unit,omitempty"`               // 假期时长单位, 可选值有: 1: 天, 2: 小时, 3: 半天, 4: 半小时
	Interval         int64      `json:"interval,omitempty"`           // 假期时长（单位: 秒）, 暂未开放提供, 待后续提供
	StartTime        string     `json:"start_time,omitempty"`         // 开始时间, 时间格式为 yyyy-MM-dd HH:mm:ss, 时间按照审批发起人当前考勤组的时区进行取值, 如果发起人已离职, 则默认为 0 时区。
	EndTime          string     `json:"end_time,omitempty"`           // 结束时间, 时间格式为 yyyy-MM-dd HH:mm:ss, 时间按照审批发起人当前考勤组的时区进行取值, 如果发起人已离职, 则默认为 0 时区。
	I18nNames        *I18nNames `json:"i18n_names,omitempty"`         // 假期多语言展示, 格式为 map, key 为 ["ch"、"en"、"ja"], 其中 ch 代表中文、en 代表英语、ja 代表日语
	DefaultLocale    string     `json:"default_locale,omitempty"`     // 默认语言类型, 由于飞书客户端支持中、英、日三种语言, 当用户切换语言时, 如果假期名称没有所对应的语言, 会使用默认语言的名称, 可选值有: ch: 中文, en: 英文, ja: 日文
	Reason           string     `json:"reason,omitempty"`             // 请假理由, 必选字段
	ApprovePassTime  string     `json:"approve_pass_time,omitempty"`  // 审批通过时间, 时间格式为 yyyy-MM-dd HH:mm:ss
	ApproveApplyTime string     `json:"approve_apply_time,omitempty"` // 审批申请时间, 时间格式为 yyyy-MM-dd HH:mm:ss
}

// GetAttendanceUserApprovalRespUserApprovalOut ...
type GetAttendanceUserApprovalRespUserApprovalOut struct {
	ApprovalID       string     `json:"approval_id,omitempty"`        // 审批实例 ID
	UniqID           string     `json:"uniq_id,omitempty"`            // 外出类型唯一 ID, 代表一种假期类型, 长度小于 14, * 此ID对应假期类型(即: i18n_names), 因此需要保证唯一
	Unit             int64      `json:"unit,omitempty"`               // 外出时长单位, 可选值有: 1: 天, 2: 小时, 3: 半天, 4: 半小时
	Interval         int64      `json:"interval,omitempty"`           // 外出时长（单位: 秒）
	StartTime        string     `json:"start_time,omitempty"`         // 开始时间, 时间格式为 yyyy-MM-dd HH:mm:ss, 时间按照审批发起人当前考勤组的时区进行取值, 如果发起人已离职, 则默认为 0 时区。
	EndTime          string     `json:"end_time,omitempty"`           // 结束时间, 时间格式为 yyyy-MM-dd HH:mm:ss, 时间按照审批发起人当前考勤组的时区进行取值, 如果发起人已离职, 则默认为 0 时区。
	I18nNames        *I18nNames `json:"i18n_names,omitempty"`         // 外出多语言展示, 格式为 map, key 为 ["ch"、"en"、"ja"], 其中 ch 代表中文、en 代表英语、ja 代表日语
	DefaultLocale    string     `json:"default_locale,omitempty"`     // 默认语言类型, 由于飞书客户端支持中、英、日三种语言, 当用户切换语言时, 如果假期名称没有所对应的语言, 会使用默认语言的名称
	Reason           string     `json:"reason,omitempty"`             // 外出理由
	ApprovePassTime  string     `json:"approve_pass_time,omitempty"`  // 审批通过时间
	ApproveApplyTime string     `json:"approve_apply_time,omitempty"` // 审批申请时间
}

// GetAttendanceUserApprovalRespUserApprovalOvertimeWork ...
type GetAttendanceUserApprovalRespUserApprovalOvertimeWork struct {
	ApprovalID string  `json:"approval_id,omitempty"` // 审批实例 ID
	Duration   float64 `json:"duration,omitempty"`    // 加班时长
	Unit       int64   `json:"unit,omitempty"`        // 加班时长单位, 可选值有: 1: 天, 2: 小时, 3: 半天, 4: 半小时
	Category   int64   `json:"category,omitempty"`    // 加班日期类型, 可选值有: 1: 工作日, 2: 休息日, 3: 节假日
	Type       int64   `json:"type,omitempty"`        // 加班规则类型, 可选值有: 0: 不关联加班规则, 1: 调休, 2: 加班费, 3: 关联加班规则, 没有调休或加班费
	StartTime  string  `json:"start_time,omitempty"`  // 开始时间, 时间格式为 yyyy-MM-dd HH:mm:ss, 时间按照审批发起人当前考勤组的时区进行取值, 如果发起人已离职, 则默认为 0 时区。
	EndTime    string  `json:"end_time,omitempty"`    // 结束时间, 时间格式为 yyyy-MM-dd HH:mm:ss, 时间按照审批发起人当前考勤组的时区进行取值, 如果发起人已离职, 则默认为 0 时区。
}

// GetAttendanceUserApprovalRespUserApprovalTrip ...
type GetAttendanceUserApprovalRespUserApprovalTrip struct {
	ApprovalID       string `json:"approval_id,omitempty"`        // 审批实例 ID
	StartTime        string `json:"start_time,omitempty"`         // 开始时间, 时间格式为 yyyy-MM-dd HH:mm:ss, 时间按照审批发起人当前考勤组的时区进行取值, 如果发起人已离职, 则默认为 0 时区。
	EndTime          string `json:"end_time,omitempty"`           // 结束时间, 时间格式为 yyyy-MM-dd HH:mm:ss, 时间按照审批发起人当前考勤组的时区进行取值, 如果发起人已离职, 则默认为 0 时区。
	Reason           string `json:"reason,omitempty"`             // 出差理由
	ApprovePassTime  string `json:"approve_pass_time,omitempty"`  // 审批通过时间, 时间格式为 yyyy-MM-dd HH:mm:ss
	ApproveApplyTime string `json:"approve_apply_time,omitempty"` // 审批申请时间, 时间格式为 yyyy-MM-dd HH:mm:ss
}

// getAttendanceUserApprovalResp ...
type getAttendanceUserApprovalResp struct {
	Code int64                          `json:"code,omitempty"` // 错误码, 非 0 表示失败
	Msg  string                         `json:"msg,omitempty"`  // 错误描述
	Data *GetAttendanceUserApprovalResp `json:"data,omitempty"`
}
