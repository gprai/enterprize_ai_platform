output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
output "application_log_group_arn" {
  value = aws_cloudwatch_log_group.application.arn
}
output "eks_log_group_arn" {
  value = aws_cloudwatch_log_group.eks.arn
}
output "fis_template_id" {
  value = aws_fis_experiment_template.pod_delete.id
}
output "availability_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.availability.arn
}
output "safety_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.safety.arn
}
