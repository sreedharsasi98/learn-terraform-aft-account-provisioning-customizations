resource "aws_iam_role" "aft_states" {
  name               = "aft-account-provisioning-customizations-role"
  assume_role_policy = templatefile("${path.module}/iam/trust-policies/states.tpl", { none = "none" })
}

resource "aws_iam_role_policy" "aft_states" {
  name = "aft-account-provisioning-customizations-policy"
  role = aws_iam_role.aft_states.id

  policy = templatefile("${path.module}/iam/role-policies/iam-aft-states.tpl", {
    account_provisioning_customizations_sfn_arn = aws_sfn_state_machine.aft_account_provisioning_customizations.arn
  })
}

resource "aws_iam_user" "admin_user" {
  name = "Sasi_AFT_User"
}

resource "aws_iam_policy_attachment" "admin_access" {
  name       = "admin-policy-attachment"
  users      = [aws_iam_user.admin_user.name]
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}