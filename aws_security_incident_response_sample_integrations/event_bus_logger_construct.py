"""
CDK construct to read events from an EventBus and put them into a CloudWatch LogGroup
"""

from aws_cdk import (
    aws_events,
    aws_events_targets,
    aws_logs,
    aws_cloudwatch_actions as actions,
    aws_iam as iam,
    aws_kms as kms,
    aws_sqs as sqs,
    aws_sns as sns,
    aws_cloudwatch as cloudwatch,
    Duration,
    RemovalPolicy,
)
from constructs import Construct


class EventBusLoggerConstruct(Construct):
    """
    CDK construct that creates a CloudWatch LogGroup and configures it as a target
    for an EventBridge Rule that matches events from a specified EventBus.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        event_bus: aws_events.IEventBus,
        log_group_name: str = None,
        log_retention: aws_logs.RetentionDays = aws_logs.RetentionDays.ONE_MONTH,
        **kwargs,
    ) -> None:
        """
        Initialize the EventBusLoggerConstruct.

        Creates a CloudWatch LogGroup and configures it as a target for an EventBridge Rule
        that matches events from the specified EventBus. Includes DLQ, alarms, and dashboard.

        Args:
            scope (Construct): The scope in which to define this construct
            construct_id (str): The ID of the construct
            event_bus (aws_events.IEventBus): The EventBus to read events from
            log_group_name (str, optional): Optional name for the CloudWatch LogGroup
            log_retention (aws_logs.RetentionDays): The number of days to retain log events
            **kwargs: Additional keyword arguments
        """
        super().__init__(scope, construct_id, **kwargs)

        # Create KMS key for the DLQ
        dlq_key = kms.Key(
            self,
            "DLQKey",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Add permissions for EventBridge to use the KMS key
        dlq_key.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("events.amazonaws.com")],
                actions=["kms:GenerateDataKey", "kms:Decrypt"],
                resources=["*"],
            )
        )

        # Create DLQ with the KMS key
        dlq = sqs.Queue(
            self,
            "deadletter-queue",
            retention_period=Duration.days(14),
            visibility_timeout=Duration.seconds(300),
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=dlq_key,
        )

        # Add HTTPS enforcement policy
        dlq.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["sqs:*"],
                resources=[dlq.queue_arn],
                conditions={"Bool": {"aws:SecureTransport": "false"}},
            )
        )

        # Grant EventBridge permissions to send messages to the DLQ
        dlq.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("events.amazonaws.com")],
                actions=["sqs:SendMessage"],
                resources=[dlq.queue_arn],
            )
        )

        # Create SNS Topic for alerts
        alarm_topic = sns.Topic(
            self,
            "DLQAlarmTopic",
            master_key=kms.Key(
                self,
                "TopicKey",
                enable_key_rotation=True,
                removal_policy=RemovalPolicy.DESTROY,
            ),
        )

        # Create metric
        dlq_messages = dlq.metric_approximate_number_of_messages_visible(
            period=Duration.minutes(1), statistic="Sum"
        )

        # Create CloudWatch Alarm
        """ This alarm checks every minute (period=Duration.minutes(1))
        Triggers immediately when messages appear (datapoints_to_alarm=1)
        Uses metric_approximate_number_of_messages_visible() or metric_number_of_messages_sent()
        Sends notification to SNS topic when triggered
        Includes a dashboard for visualization """
        alarm = cloudwatch.Alarm(
            self,
            "DLQMessagesAlarm",
            metric=dlq_messages,
            threshold=0,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            evaluation_periods=1,
            datapoints_to_alarm=1,  # Trigger as soon as one datapoint exceeds threshold
            alarm_description="Alarm when messages are present in DLQ",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        # Add SNS action to alarm
        alarm.add_alarm_action(actions.SnsAction(alarm_topic))

        # Create a dashboard
        dashboard = cloudwatch.Dashboard(self, "DLQDashboard")

        dashboard.add_widgets(
            cloudwatch.GraphWidget(title="DLQ Messages", left=[dlq_messages])
        )

        # Create a CloudWatch LogGroup
        self.log_group = aws_logs.LogGroup(
            self,
            "LogGroup",
            log_group_name=log_group_name or f"/aws/events/{event_bus.event_bus_name}",
            retention=log_retention,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Create an EventBridge Rule that matches all events from the EventBus
        rule = aws_events.Rule(
            self,
            "EventBusLoggerRule",
            event_bus=event_bus,
            description=f"Rule to log all events from {event_bus.event_bus_name} to CloudWatch Logs",
            # Match all events from the security-ir-poller source
            event_pattern=aws_events.EventPattern(source=["security-ir-poller"]),
        )

        # Add the CloudWatch LogGroup as a target for the rule
        rule.add_target(
            aws_events_targets.CloudWatchLogGroup(
                self.log_group,
                dead_letter_queue=dlq,
                retry_attempts=2,
                max_event_age=Duration.minutes(1),
            )
        )
