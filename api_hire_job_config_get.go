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

// GetHireJobConfig 获取职位设置
//
// doc: https://open.feishu.cn/document/ukTMukTMukTM/uMzM1YjLzMTN24yMzUjN/hire-v1/job/config
func (r *HireService) GetHireJobConfig(ctx context.Context, request *GetHireJobConfigReq, options ...MethodOptionFunc) (*GetHireJobConfigResp, *Response, error) {
	if r.cli.mock.mockHireGetHireJobConfig != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Hire#GetHireJobConfig mock enable")
		return r.cli.mock.mockHireGetHireJobConfig(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Hire",
		API:                   "GetHireJobConfig",
		Method:                "GET",
		URL:                   r.cli.openBaseURL + "/open-apis/hire/v1/jobs/:job_id/config",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(getHireJobConfigResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

// MockHireGetHireJobConfig mock HireGetHireJobConfig method
func (r *Mock) MockHireGetHireJobConfig(f func(ctx context.Context, request *GetHireJobConfigReq, options ...MethodOptionFunc) (*GetHireJobConfigResp, *Response, error)) {
	r.mockHireGetHireJobConfig = f
}

// UnMockHireGetHireJobConfig un-mock HireGetHireJobConfig method
func (r *Mock) UnMockHireGetHireJobConfig() {
	r.mockHireGetHireJobConfig = nil
}

// GetHireJobConfigReq ...
type GetHireJobConfigReq struct {
	JobID      string  `path:"job_id" json:"-"`        // 职位 ID, 示例值: "6960663240925956660"
	UserIDType *IDType `query:"user_id_type" json:"-"` // 用户 ID 类型, 示例值: "open_id", 可选值有: open_id: 标识一个用户在某个应用中的身份。同一个用户在不同应用中的 Open ID 不同。[了解更多: 如何获取 Open ID](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-openid), union_id: 标识一个用户在某个应用开发商下的身份。同一用户在同一开发商下的应用中的 Union ID 是相同的, 在不同开发商下的应用中的 Union ID 是不同的。通过 Union ID, 应用开发商可以把同个用户在多个应用中的身份关联起来。[了解更多: 如何获取 Union ID？](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-union-id), user_id: 标识一个用户在某个租户内的身份。同一个用户在租户 A 和租户 B 内的 User ID 是不同的。在同一个租户内, 一个用户的 User ID 在所有应用（包括商店应用）中都保持一致。User ID 主要用于在不同的应用间打通用户数据。[了解更多: 如何获取 User ID？](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-user-id), people_admin_id: 以people_admin_id来识别用户, 默认值: `open_id`, 当值为 `user_id`, 字段权限要求: 获取用户 user ID
}

// GetHireJobConfigResp ...
type GetHireJobConfigResp struct {
	JobConfig *GetHireJobConfigRespJobConfig `json:"job_config,omitempty"` // 职位配置
}

// GetHireJobConfigRespJobConfig ...
type GetHireJobConfigRespJobConfig struct {
	OfferApplySchema         *GetHireJobConfigRespJobConfigOfferApplySchema       `json:"offer_apply_schema,omitempty"`         // Offer 申请表
	OfferProcessConf         *GetHireJobConfigRespJobConfigOfferProcessConf       `json:"offer_process_conf,omitempty"`         // Offer 审批流
	RecommendedEvaluatorList []*GetHireJobConfigRespJobConfigRecommendedEvaluator `json:"recommended_evaluator_list,omitempty"` // 建议评估人列表
	AssessmentTemplate       *GetHireJobConfigRespJobConfigAssessmentTemplate     `json:"assessment_template,omitempty"`        // 面试评价表
	ID                       string                                               `json:"id,omitempty"`                         // 职位 ID
	InterviewRoundList       []*GetHireJobConfigRespJobConfigInterviewRound       `json:"interview_round_list,omitempty"`       // 建议面试官列表
	JobRequirementList       []*GetHireJobConfigRespJobConfigJobRequirement       `json:"job_requirement_list,omitempty"`       // 招聘需求
	InterviewRoundTypeList   []*GetHireJobConfigRespJobConfigInterviewRoundType   `json:"interview_round_type_list,omitempty"`  // 面试轮次类型列表
	RelatedJobList           []*GetHireJobConfigRespJobConfigRelatedJob           `json:"related_job_list,omitempty"`           // 关联职位列表
	JobAttribute             int64                                                `json:"job_attribute,omitempty"`              // 职位属性, 1是实体职位, 2是虚拟职位
}

// GetHireJobConfigRespJobConfigAssessmentTemplate ...
type GetHireJobConfigRespJobConfigAssessmentTemplate struct {
	ID   string                                               `json:"id,omitempty"`   // ID
	Name *GetHireJobConfigRespJobConfigAssessmentTemplateName `json:"name,omitempty"` // 名称
}

// GetHireJobConfigRespJobConfigAssessmentTemplateName ...
type GetHireJobConfigRespJobConfigAssessmentTemplateName struct {
	ZhCn string `json:"zh_cn,omitempty"` // 中文
	EnUs string `json:"en_us,omitempty"` // 英文
}

// GetHireJobConfigRespJobConfigInterviewRound ...
type GetHireJobConfigRespJobConfigInterviewRound struct {
	InterviewerList []*GetHireJobConfigRespJobConfigInterviewRoundInterviewer `json:"interviewer_list,omitempty"` // 面试官列表
	Round           int64                                                     `json:"round,omitempty"`            // 面试轮次
}

// GetHireJobConfigRespJobConfigInterviewRoundInterviewer ...
type GetHireJobConfigRespJobConfigInterviewRoundInterviewer struct {
	ID   string                                                      `json:"id,omitempty"`   // ID
	Name *GetHireJobConfigRespJobConfigInterviewRoundInterviewerName `json:"name,omitempty"` // 名称
}

// GetHireJobConfigRespJobConfigInterviewRoundInterviewerName ...
type GetHireJobConfigRespJobConfigInterviewRoundInterviewerName struct {
	ZhCn string `json:"zh_cn,omitempty"` // 中文
	EnUs string `json:"en_us,omitempty"` // 英文
}

// GetHireJobConfigRespJobConfigInterviewRoundType ...
type GetHireJobConfigRespJobConfigInterviewRoundType struct {
	AssessmentRound    *GetHireJobConfigRespJobConfigInterviewRoundTypeAssessmentRound    `json:"assessment_round,omitempty"`    // 面试轮次类型
	AssessmentTemplate *GetHireJobConfigRespJobConfigInterviewRoundTypeAssessmentTemplate `json:"assessment_template,omitempty"` // 面试评价表
}

// GetHireJobConfigRespJobConfigInterviewRoundTypeAssessmentRound ...
type GetHireJobConfigRespJobConfigInterviewRoundTypeAssessmentRound struct {
	ID   string                                                              `json:"id,omitempty"`   // ID
	Name *GetHireJobConfigRespJobConfigInterviewRoundTypeAssessmentRoundName `json:"name,omitempty"` // 名称
}

// GetHireJobConfigRespJobConfigInterviewRoundTypeAssessmentRoundName ...
type GetHireJobConfigRespJobConfigInterviewRoundTypeAssessmentRoundName struct {
	ZhCn string `json:"zh_cn,omitempty"` // 中文
	EnUs string `json:"en_us,omitempty"` // 英文
}

// GetHireJobConfigRespJobConfigInterviewRoundTypeAssessmentTemplate ...
type GetHireJobConfigRespJobConfigInterviewRoundTypeAssessmentTemplate struct {
	ID   string                                                                 `json:"id,omitempty"`   // ID
	Name *GetHireJobConfigRespJobConfigInterviewRoundTypeAssessmentTemplateName `json:"name,omitempty"` // 名称
}

// GetHireJobConfigRespJobConfigInterviewRoundTypeAssessmentTemplateName ...
type GetHireJobConfigRespJobConfigInterviewRoundTypeAssessmentTemplateName struct {
	ZhCn string `json:"zh_cn,omitempty"` // 中文
	EnUs string `json:"en_us,omitempty"` // 英文
}

// GetHireJobConfigRespJobConfigJobRequirement ...
type GetHireJobConfigRespJobConfigJobRequirement struct {
	ID   string                                           `json:"id,omitempty"`   // ID
	Name *GetHireJobConfigRespJobConfigJobRequirementName `json:"name,omitempty"` // 名称
}

// GetHireJobConfigRespJobConfigJobRequirementName ...
type GetHireJobConfigRespJobConfigJobRequirementName struct {
	ZhCn string `json:"zh_cn,omitempty"` // 中文
	EnUs string `json:"en_us,omitempty"` // 英文
}

// GetHireJobConfigRespJobConfigOfferApplySchema ...
type GetHireJobConfigRespJobConfigOfferApplySchema struct {
	ID   string                                             `json:"id,omitempty"`   // ID
	Name *GetHireJobConfigRespJobConfigOfferApplySchemaName `json:"name,omitempty"` // 名称
}

// GetHireJobConfigRespJobConfigOfferApplySchemaName ...
type GetHireJobConfigRespJobConfigOfferApplySchemaName struct {
	ZhCn string `json:"zh_cn,omitempty"` // 中文
	EnUs string `json:"en_us,omitempty"` // 英文
}

// GetHireJobConfigRespJobConfigOfferProcessConf ...
type GetHireJobConfigRespJobConfigOfferProcessConf struct {
	ID   string                                             `json:"id,omitempty"`   // ID
	Name *GetHireJobConfigRespJobConfigOfferProcessConfName `json:"name,omitempty"` // 名称
}

// GetHireJobConfigRespJobConfigOfferProcessConfName ...
type GetHireJobConfigRespJobConfigOfferProcessConfName struct {
	ZhCn string `json:"zh_cn,omitempty"` // 中文
	EnUs string `json:"en_us,omitempty"` // 英文
}

// GetHireJobConfigRespJobConfigRecommendedEvaluator ...
type GetHireJobConfigRespJobConfigRecommendedEvaluator struct {
	ID   string                                                 `json:"id,omitempty"`   // ID
	Name *GetHireJobConfigRespJobConfigRecommendedEvaluatorName `json:"name,omitempty"` // 名称
}

// GetHireJobConfigRespJobConfigRecommendedEvaluatorName ...
type GetHireJobConfigRespJobConfigRecommendedEvaluatorName struct {
	ZhCn string `json:"zh_cn,omitempty"` // 中文
	EnUs string `json:"en_us,omitempty"` // 英文
}

// GetHireJobConfigRespJobConfigRelatedJob ...
type GetHireJobConfigRespJobConfigRelatedJob struct {
	ID   string                                       `json:"id,omitempty"`   // ID
	Name *GetHireJobConfigRespJobConfigRelatedJobName `json:"name,omitempty"` // 名称
}

// GetHireJobConfigRespJobConfigRelatedJobName ...
type GetHireJobConfigRespJobConfigRelatedJobName struct {
	ZhCn string `json:"zh_cn,omitempty"` // 中文
	EnUs string `json:"en_us,omitempty"` // 英文
}

// getHireJobConfigResp ...
type getHireJobConfigResp struct {
	Code int64                 `json:"code,omitempty"` // 错误码, 非 0 表示失败
	Msg  string                `json:"msg,omitempty"`  // 错误描述
	Data *GetHireJobConfigResp `json:"data,omitempty"`
}