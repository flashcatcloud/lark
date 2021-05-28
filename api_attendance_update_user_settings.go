// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// UpdateAttendanceUserSettings
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/Attendance//rule/user-setting-modify
func (r *AttendanceService) UpdateAttendanceUserSettings(ctx context.Context, request *UpdateAttendanceUserSettingsReq, options ...MethodOptionFunc) (*UpdateAttendanceUserSettingsResp, *Response, error) {
	if r.cli.mock.mockAttendanceUpdateAttendanceUserSettings != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Attendance#UpdateAttendanceUserSettings mock enable")
		return r.cli.mock.mockAttendanceUpdateAttendanceUserSettings(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Attendance",
		API:                   "UpdateAttendanceUserSettings",
		Method:                "POST",
		URL:                   "https://open.feishu.cn/open-apis/attendance/v1/user_settings/modify",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(updateAttendanceUserSettingsResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockAttendanceUpdateAttendanceUserSettings(f func(ctx context.Context, request *UpdateAttendanceUserSettingsReq, options ...MethodOptionFunc) (*UpdateAttendanceUserSettingsResp, *Response, error)) {
	r.mockAttendanceUpdateAttendanceUserSettings = f
}

func (r *Mock) UnMockAttendanceUpdateAttendanceUserSettings() {
	r.mockAttendanceUpdateAttendanceUserSettings = nil
}

type UpdateAttendanceUserSettingsReq struct {
	EmployeeType EmployeeType                                `query:"employee_type" json:"-"` // 用户类型, 可选值有: `employee_id`： 员工id, `employee_no`： 员工工号
	UserSetting  *UpdateAttendanceUserSettingsReqUserSetting `json:"user_setting,omitempty"`  // 用户信息
}

type UpdateAttendanceUserSettingsReqUserSetting struct {
	UserID  string `json:"user_id,omitempty"`  // 用户id
	FaceKey string `json:"face_key,omitempty"` // 人脸照片key（通过文件上传接口得到）
}

type updateAttendanceUserSettingsResp struct {
	Code int64                             `json:"code,omitempty"` // 错误码，非 0 表示失败
	Msg  string                            `json:"msg,omitempty"`  // 错误描述
	Data *UpdateAttendanceUserSettingsResp `json:"data,omitempty"`
}

type UpdateAttendanceUserSettingsResp struct {
	UserSetting *UpdateAttendanceUserSettingsRespUserSetting `json:"user_setting,omitempty"` // 用户设置
}

type UpdateAttendanceUserSettingsRespUserSetting struct {
	UserID  string `json:"user_id,omitempty"`  // 用户id
	FaceKey string `json:"face_key,omitempty"` // 人脸照片key
}
