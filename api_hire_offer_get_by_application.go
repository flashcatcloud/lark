// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// GetHireOfferByApplication 根据投递 ID 获取 Offer 信息
//
// doc: https://open.feishu.cn/document/ukTMukTMukTM/uMzM1YjLzMTN24yMzUjN/hire-v1/application/offer
func (r *HireService) GetHireOfferByApplication(ctx context.Context, request *GetHireOfferByApplicationReq, options ...MethodOptionFunc) (*GetHireOfferByApplicationResp, *Response, error) {
	if r.cli.mock.mockHireGetHireOfferByApplication != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Hire#GetHireOfferByApplication mock enable")
		return r.cli.mock.mockHireGetHireOfferByApplication(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Hire",
		API:                   "GetHireOfferByApplication",
		Method:                "GET",
		URL:                   "https://open.feishu.cn/open-apis/hire/v1/applications/:application_id/offer",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(getHireOfferByApplicationResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockHireGetHireOfferByApplication(f func(ctx context.Context, request *GetHireOfferByApplicationReq, options ...MethodOptionFunc) (*GetHireOfferByApplicationResp, *Response, error)) {
	r.mockHireGetHireOfferByApplication = f
}

func (r *Mock) UnMockHireGetHireOfferByApplication() {
	r.mockHireGetHireOfferByApplication = nil
}

type GetHireOfferByApplicationReq struct {
	UserIDType    *IDType `query:"user_id_type" json:"-"`  // 用户 ID 类型, 示例值："open_id", 可选值有: `open_id`：用户的 open id, `union_id`：用户的 union id, `user_id`：用户的 user id, 默认值: `open_id`, 当值为 `user_id`, 字段权限要求: 获取用户 userid
	ApplicationID string  `path:"application_id" json:"-"` // 投递ID, 示例值："12312312312"
}

type getHireOfferByApplicationResp struct {
	Code int64                          `json:"code,omitempty"` // 错误码，非 0 表示失败
	Msg  string                         `json:"msg,omitempty"`  // 错误描述
	Data *GetHireOfferByApplicationResp `json:"data,omitempty"`
}

type GetHireOfferByApplicationResp struct {
	Offer *GetHireOfferByApplicationRespOffer `json:"offer,omitempty"` // Offer数据
}

type GetHireOfferByApplicationRespOffer struct {
	ID            string                                        `json:"id,omitempty"`             // Offer id
	ApplicationID string                                        `json:"application_id,omitempty"` // 投递id
	BasicInfo     *GetHireOfferByApplicationRespOfferBasicInfo  `json:"basic_info,omitempty"`     // 基础信息
	SalaryPlan    *GetHireOfferByApplicationRespOfferSalaryPlan `json:"salary_plan,omitempty"`    // 薪酬计划
	SchemaID      string                                        `json:"schema_id,omitempty"`      // 当前offer使用的schema
	OfferStatus   int64                                         `json:"offer_status,omitempty"`   // Offer状态, 可选值有: `0`：所有, `1`：未申请, `2`：审批中, `3`：审批已撤回, `4`：审批通过, `5`：审批不通过, `6`：Offer 已发出, `7`：候选人已接受, `8`：候选人已拒绝, `9`：Offer 已失效
}

type GetHireOfferByApplicationRespOfferBasicInfo struct {
	OfferType         int64                                                       `json:"offer_type,omitempty"`          // Offer类型 1=Social, 2=Campus, 3=Intern, 4=InternTransfer, 可选值有: `1`：Social, `2`：Campus, `3`：Intern, `4`：InternTransfer
	Remark            string                                                      `json:"remark,omitempty"`              // 备注
	ExpireTime        int64                                                       `json:"expire_time,omitempty"`         // Offer过期时间
	OwnerUserID       string                                                      `json:"owner_user_id,omitempty"`       // string
	LeaderUserID      string                                                      `json:"leader_user_id,omitempty"`      // string
	OnboardDate       string                                                      `json:"onboard_date,omitempty"`        // 入职日期
	DepartmentID      string                                                      `json:"department_id,omitempty"`       // 入职部门
	ProbationMonth    int64                                                       `json:"probation_month,omitempty"`     // 试用期, 比如试用期6个月
	ContractYear      int64                                                       `json:"contract_year,omitempty"`       // 合同期, 比如3年
	RecruitmentType   *GetHireOfferByApplicationRespOfferBasicInfoRecruitmentType `json:"recruitment_type,omitempty"`    // 雇员类型
	Sequence          *GetHireOfferByApplicationRespOfferBasicInfoSequence        `json:"sequence,omitempty"`            // 序列
	Level             *GetHireOfferByApplicationRespOfferBasicInfoLevel           `json:"level,omitempty"`               // 级别
	OnboardAddress    *GetHireOfferByApplicationRespOfferBasicInfoOnboardAddress  `json:"onboard_address,omitempty"`     // 入职地点
	WorkAddress       *GetHireOfferByApplicationRespOfferBasicInfoWorkAddress     `json:"work_address,omitempty"`        // 工作地点
	CustomizeInfoList []*GetHireOfferByApplicationRespOfferBasicInfoCustomizeInfo `json:"customize_info_list,omitempty"` // 自定义字段的value信息
}

type GetHireOfferByApplicationRespOfferBasicInfoRecruitmentType struct {
	ID     string `json:"id,omitempty"`      // ID
	ZhName string `json:"zh_name,omitempty"` // 中文名称
	EnName string `json:"en_name,omitempty"` // 英文名称
}

type GetHireOfferByApplicationRespOfferBasicInfoSequence struct {
	ID     string `json:"id,omitempty"`      // ID
	ZhName string `json:"zh_name,omitempty"` // 中文名称
	EnName string `json:"en_name,omitempty"` // 英文名称
}

type GetHireOfferByApplicationRespOfferBasicInfoLevel struct {
	ID     string `json:"id,omitempty"`      // ID
	ZhName string `json:"zh_name,omitempty"` // 中文名称
	EnName string `json:"en_name,omitempty"` // 英文名称
}

type GetHireOfferByApplicationRespOfferBasicInfoOnboardAddress struct {
	ID       string                                                             `json:"id,omitempty"`       // ID
	ZhName   string                                                             `json:"zh_name,omitempty"`  // 中文名称
	EnName   string                                                             `json:"en_name,omitempty"`  // 英文名称
	District *GetHireOfferByApplicationRespOfferBasicInfoOnboardAddressDistrict `json:"district,omitempty"` // 区域信息
	City     *GetHireOfferByApplicationRespOfferBasicInfoOnboardAddressCity     `json:"city,omitempty"`     // 城市信息
	State    *GetHireOfferByApplicationRespOfferBasicInfoOnboardAddressState    `json:"state,omitempty"`    // 省信息
	Country  *GetHireOfferByApplicationRespOfferBasicInfoOnboardAddressCountry  `json:"country,omitempty"`  // 国家信息
}

type GetHireOfferByApplicationRespOfferBasicInfoOnboardAddressDistrict struct {
	ZhName       string `json:"zh_name,omitempty"`       // 中文名称
	EnName       string `json:"en_name,omitempty"`       // 英文名称
	Code         string `json:"code,omitempty"`          // 编码
	LocationType int64  `json:"location_type,omitempty"` // 地址类型 1=COUNTRY, 2=STATE, 3=CITY, 4=DISTRICT, 5=ADDRESS,
}

type GetHireOfferByApplicationRespOfferBasicInfoOnboardAddressCity struct {
	ZhName       string `json:"zh_name,omitempty"`       // 中文名称
	EnName       string `json:"en_name,omitempty"`       // 英文名称
	Code         string `json:"code,omitempty"`          // 编码
	LocationType int64  `json:"location_type,omitempty"` // 地址类型 1=COUNTRY, 2=STATE, 3=CITY, 4=DISTRICT, 5=ADDRESS,, 可选值有: `1`：COUNTRY, `2`：STATE, `3`：CITY, `4`：DISTRICT, `5`：ADDRESS
}

type GetHireOfferByApplicationRespOfferBasicInfoOnboardAddressState struct {
	ZhName       string `json:"zh_name,omitempty"`       // 中文名称
	EnName       string `json:"en_name,omitempty"`       // 英文名称
	Code         string `json:"code,omitempty"`          // 编码
	LocationType int64  `json:"location_type,omitempty"` // 地址类型 1=COUNTRY, 2=STATE, 3=CITY, 4=DISTRICT, 5=ADDRESS,, 可选值有: `1`：COUNTRY, `2`：STATE, `3`：CITY, `4`：DISTRICT, `5`：ADDRESS
}

type GetHireOfferByApplicationRespOfferBasicInfoOnboardAddressCountry struct {
	ZhName       string `json:"zh_name,omitempty"`       // 中文名称
	EnName       string `json:"en_name,omitempty"`       // 英文名称
	Code         string `json:"code,omitempty"`          // 编码
	LocationType int64  `json:"location_type,omitempty"` // 地址类型 1=COUNTRY, 2=STATE, 3=CITY, 4=DISTRICT, 5=ADDRESS,, 可选值有: `1`：COUNTRY, `2`：STATE, `3`：CITY, `4`：DISTRICT, `5`：ADDRESS
}

type GetHireOfferByApplicationRespOfferBasicInfoWorkAddress struct {
	ID       string                                                          `json:"id,omitempty"`       // ID
	ZhName   string                                                          `json:"zh_name,omitempty"`  // 中文名称
	EnName   string                                                          `json:"en_name,omitempty"`  // 英文名称
	District *GetHireOfferByApplicationRespOfferBasicInfoWorkAddressDistrict `json:"district,omitempty"` // 区域信息
	City     *GetHireOfferByApplicationRespOfferBasicInfoWorkAddressCity     `json:"city,omitempty"`     // 城市信息
	State    *GetHireOfferByApplicationRespOfferBasicInfoWorkAddressState    `json:"state,omitempty"`    // 省信息
	Country  *GetHireOfferByApplicationRespOfferBasicInfoWorkAddressCountry  `json:"country,omitempty"`  // 国家信息
}

type GetHireOfferByApplicationRespOfferBasicInfoWorkAddressDistrict struct {
	ZhName       string `json:"zh_name,omitempty"`       // 中文名称
	EnName       string `json:"en_name,omitempty"`       // 英文名称
	Code         string `json:"code,omitempty"`          // 编码
	LocationType int64  `json:"location_type,omitempty"` // 地址类型 1=COUNTRY, 2=STATE, 3=CITY, 4=DISTRICT, 5=ADDRESS,
}

type GetHireOfferByApplicationRespOfferBasicInfoWorkAddressCity struct {
	ZhName       string `json:"zh_name,omitempty"`       // 中文名称
	EnName       string `json:"en_name,omitempty"`       // 英文名称
	Code         string `json:"code,omitempty"`          // 编码
	LocationType int64  `json:"location_type,omitempty"` // 地址类型 1=COUNTRY, 2=STATE, 3=CITY, 4=DISTRICT, 5=ADDRESS,, 可选值有: `1`：COUNTRY, `2`：STATE, `3`：CITY, `4`：DISTRICT, `5`：ADDRESS
}

type GetHireOfferByApplicationRespOfferBasicInfoWorkAddressState struct {
	ZhName       string `json:"zh_name,omitempty"`       // 中文名称
	EnName       string `json:"en_name,omitempty"`       // 英文名称
	Code         string `json:"code,omitempty"`          // 编码
	LocationType int64  `json:"location_type,omitempty"` // 地址类型 1=COUNTRY, 2=STATE, 3=CITY, 4=DISTRICT, 5=ADDRESS,, 可选值有: `1`：COUNTRY, `2`：STATE, `3`：CITY, `4`：DISTRICT, `5`：ADDRESS
}

type GetHireOfferByApplicationRespOfferBasicInfoWorkAddressCountry struct {
	ZhName       string `json:"zh_name,omitempty"`       // 中文名称
	EnName       string `json:"en_name,omitempty"`       // 英文名称
	Code         string `json:"code,omitempty"`          // 编码
	LocationType int64  `json:"location_type,omitempty"` // 地址类型 1=COUNTRY, 2=STATE, 3=CITY, 4=DISTRICT, 5=ADDRESS,, 可选值有: `1`：COUNTRY, `2`：STATE, `3`：CITY, `4`：DISTRICT, `5`：ADDRESS
}

type GetHireOfferByApplicationRespOfferBasicInfoCustomizeInfo struct {
	ObjectID       string `json:"object_id,omitempty"`       // 自定义字段ID
	CustomizeValue string `json:"customize_value,omitempty"` // 自定义字段Value
}

type GetHireOfferByApplicationRespOfferSalaryPlan struct {
	Currency                  string                                                       `json:"currency,omitempty"`                    // 币种
	BasicSalary               string                                                       `json:"basic_salary,omitempty"`                // 基本薪资, 注意是json
	ProbationSalaryPercentage string                                                       `json:"probation_salary_percentage,omitempty"` // 试用期百分比
	AwardSalaryMultiple       string                                                       `json:"award_salary_multiple,omitempty"`       // 年终奖月数
	OptionShares              string                                                       `json:"option_shares,omitempty"`               // 期权股数
	QuarterlyBonus            string                                                       `json:"quarterly_bonus,omitempty"`             // 季度奖金额
	HalfYearBonus             string                                                       `json:"half_year_bonus,omitempty"`             // 半年奖金额
	TotalAnnualCash           string                                                       `json:"total_annual_cash,omitempty"`           // 年度现金总额(数量，非公式)
	CustomizeInfoList         []*GetHireOfferByApplicationRespOfferSalaryPlanCustomizeInfo `json:"customize_info_list,omitempty"`         // 自定义字段的value信息
}

type GetHireOfferByApplicationRespOfferSalaryPlanCustomizeInfo struct {
	ObjectID       string `json:"object_id,omitempty"`       // 自定义字段ID
	CustomizeValue string `json:"customize_value,omitempty"` // 自定义字段Value
}
