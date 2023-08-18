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

// AddHireTalentToFolder 将人才加入指定文件夹。
//
// doc: https://open.feishu.cn/document/ukTMukTMukTM/uMzM1YjLzMTN24yMzUjN/hire-v1/talent/add_to_folder
// new doc: https://open.feishu.cn/document/server-docs/hire-v1/candidate-management/talent/add_to_folder
func (r *HireService) AddHireTalentToFolder(ctx context.Context, request *AddHireTalentToFolderReq, options ...MethodOptionFunc) (*AddHireTalentToFolderResp, *Response, error) {
	if r.cli.mock.mockHireAddHireTalentToFolder != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Hire#AddHireTalentToFolder mock enable")
		return r.cli.mock.mockHireAddHireTalentToFolder(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Hire",
		API:                   "AddHireTalentToFolder",
		Method:                "POST",
		URL:                   r.cli.openBaseURL + "/open-apis/hire/v1/talents/add_to_folder",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(addHireTalentToFolderResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

// MockHireAddHireTalentToFolder mock HireAddHireTalentToFolder method
func (r *Mock) MockHireAddHireTalentToFolder(f func(ctx context.Context, request *AddHireTalentToFolderReq, options ...MethodOptionFunc) (*AddHireTalentToFolderResp, *Response, error)) {
	r.mockHireAddHireTalentToFolder = f
}

// UnMockHireAddHireTalentToFolder un-mock HireAddHireTalentToFolder method
func (r *Mock) UnMockHireAddHireTalentToFolder() {
	r.mockHireAddHireTalentToFolder = nil
}

// AddHireTalentToFolderReq ...
type AddHireTalentToFolderReq struct {
	TalentIDList []string `json:"talent_id_list,omitempty"` // 人才 ID 列表, 示例值: ["7039620186502138157"], 最大长度: `50`
	FolderID     *string  `json:"folder_id,omitempty"`      // 文件夹 ID, 示例值: "7039620186502138156"
}

// AddHireTalentToFolderResp ...
type AddHireTalentToFolderResp struct {
	TalentIDList []string `json:"talent_id_list,omitempty"` // 人才 ID 列表
	FolderID     string   `json:"folder_id,omitempty"`      // 文件夹 ID
}

// addHireTalentToFolderResp ...
type addHireTalentToFolderResp struct {
	Code int64                      `json:"code,omitempty"` // 错误码, 非 0 表示失败
	Msg  string                     `json:"msg,omitempty"`  // 错误描述
	Data *AddHireTalentToFolderResp `json:"data,omitempty"`
}
