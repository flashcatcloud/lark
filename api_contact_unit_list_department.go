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

// GetContactUnitDepartmentList 通过该接口获取单位绑定的部门列表, 需具有获取单位的权限
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/contact-v3/unit/list_department
func (r *ContactService) GetContactUnitDepartmentList(ctx context.Context, request *GetContactUnitDepartmentListReq, options ...MethodOptionFunc) (*GetContactUnitDepartmentListResp, *Response, error) {
	if r.cli.mock.mockContactGetContactUnitDepartmentList != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Contact#GetContactUnitDepartmentList mock enable")
		return r.cli.mock.mockContactGetContactUnitDepartmentList(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Contact",
		API:                   "GetContactUnitDepartmentList",
		Method:                "GET",
		URL:                   r.cli.openBaseURL + "/open-apis/contact/v3/unit/list_department",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(getContactUnitDepartmentListResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

// MockContactGetContactUnitDepartmentList mock ContactGetContactUnitDepartmentList method
func (r *Mock) MockContactGetContactUnitDepartmentList(f func(ctx context.Context, request *GetContactUnitDepartmentListReq, options ...MethodOptionFunc) (*GetContactUnitDepartmentListResp, *Response, error)) {
	r.mockContactGetContactUnitDepartmentList = f
}

// UnMockContactGetContactUnitDepartmentList un-mock ContactGetContactUnitDepartmentList method
func (r *Mock) UnMockContactGetContactUnitDepartmentList() {
	r.mockContactGetContactUnitDepartmentList = nil
}

// GetContactUnitDepartmentListReq ...
type GetContactUnitDepartmentListReq struct {
	UnitID           string            `query:"unit_id" json:"-"`            // 单位ID, 示例值: "BU121"
	DepartmentIDType *DepartmentIDType `query:"department_id_type" json:"-"` // 此次调用中预获取的部门ID的类型, 示例值: "open_department_id", 可选值有: `department_id`: 以自定义department_id来标识部门, `open_department_id`: 以open_department_id来标识部门, 默认值: `open_department_id`
	PageToken        *string           `query:"page_token" json:"-"`         // 分页标记, 第一次请求不填, 表示从头开始遍历；分页查询结果还有更多项时会同时返回新的 page_token, 下次遍历可采用该 page_token 获取查询结果, 示例值: "AQD9/Rn9eij9Pm39ED40/dk53s4Ebp882DYfFaPFbz00L4CMZJrqGdzNyc8BcZtDbwVUvRmQTvyMYicnGWrde9X56TgdBuS+JKiSIkdexPw="
	PageSize         *int64            `query:"page_size" json:"-"`          // 分页大小, 示例值: 50, 默认值: `50`, 最大值: `100`
}

// GetContactUnitDepartmentListResp ...
type GetContactUnitDepartmentListResp struct {
	Departmentlist []*GetContactUnitDepartmentListRespDepartment `json:"departmentlist,omitempty"` // 单位绑定的部门列表
	HasMore        bool                                          `json:"has_more,omitempty"`       // 是否还有分页数据
	PageToken      string                                        `json:"page_token,omitempty"`     // 下次分页请求标记
}

// GetContactUnitDepartmentListRespDepartment ...
type GetContactUnitDepartmentListRespDepartment struct {
	UnitID       string `json:"unit_id,omitempty"`       // 单位ID
	DepartmentID string `json:"department_id,omitempty"` // 部门ID
}

// getContactUnitDepartmentListResp ...
type getContactUnitDepartmentListResp struct {
	Code int64                             `json:"code,omitempty"` // 错误码, 非 0 表示失败
	Msg  string                            `json:"msg,omitempty"`  // 错误描述
	Data *GetContactUnitDepartmentListResp `json:"data,omitempty"`
}