{% ifversion fpt or ghes or ghec %}
1. 任何失败的步骤都会自动展开以显示结果。
   {% ifversion fpt or ghes > 3.0 or ghec %}
   ![Super linter 工作流程结果](/assets/images/help/repository/super-linter-workflow-results-updated-2.png){% else %}
![Super linter workflow results](/assets/images/help/repository/super-linter-workflow-results-updated.png){% endif %}
{% else %}
1. 展开**运行 Super-Linter** 步骤以查看结果。 ![Super linter 工作流程结果](/assets/images/help/repository/super-linter-workflow-results.png)
{% endif %}
