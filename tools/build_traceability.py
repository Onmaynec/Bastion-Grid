"""Preserve every RFP item; never infer acceptance from presence of a feature."""
import json
from pathlib import Path

PARTIAL = {
 'WIN-007':['test_collector_queue_cap_preserves_oldest','test_collector_restart_preserves_event_ids'],
 'LNX-008':['test_collector_byte_cap','test_collector_lost_ack_replays_identical_event'],
 'WIN-011':['test_collector_cli_sample_and_status'],
 'IAM-002':['test_revocation_invalidates_cookie','test_logout_invalidates_session'],
 'IAM-004':['test_asset_group_and_sensitivity_filter','test_assigned_only_cases_and_related_objects'], 'IAM-006':['test_approval_quorum_and_no_execution','test_self_approval_even_if_role_elevated'],
 'IAM-009':['test_revocation_immediate','test_rotation_invalidates_all_target_cookies_and_old_bearer'],
 'IAM-010':['test_sessions_list_hides_secrets','test_revoke_one_session_keeps_other'],
 'OPS-009':['test_v1_upgrade_preserves_data_and_keys_closes_sessions','test_future_schema_fails_closed','test_v2_to_v3_preserves_live_sessions_and_event_state'], 'IAM-011':['test_cross_tenant_transition','test_10000_scoped_reads'],
 'IAM-012':['test_role_denial_audited'], 'TEN-001':['test_tenant_from_server_only'],
 'TEN-002':['test_10000_scoped_reads','test_search_cursor_and_filter'], 'TEN-012':['test_10000_scoped_reads'],
 'AST-001':['test_durable_ack_restart_and_dedup'], 'AST-006':['test_http_create_and_tenant_spoof'],
 'ING-002':['test_bad_event_time_and_oversize'], 'ING-004':['test_concurrent_dedup','test_idempotency_conflict_rolls_back_batch'],
 'ING-003':['test_registered_source_binds_collector_and_assets','test_admin_cannot_spoof_registered_collector'],
 'ING-005':['test_durable_ack_restart_and_dedup'],
 'ING-006':['test_backpressure_relieved_after_processing'],
 'ING-009':['test_three_attempts_dead_letter_and_redacted_metadata','test_manual_retry_does_not_duplicate_logical_effects'],
 'ING-013':['test_health_routes_and_error_contract'],
 'ING-014':['test_poison_event_does_not_rollback_healthy_event'],
 'TEN-005':['test_quota_concurrency_cannot_oversubscribe','test_one_tenant_quota_does_not_block_another'], 'ING-011':['test_bad_event_time_and_oversize'],
 'ING-015':['test_search_cursor_and_filter','test_search_half_open_timezone_range','test_filtered_cursor_has_no_duplicates'], 'STO-009':['test_tampered_payload_and_metadata'],
 'DET-001':['test_no_self_publish','test_rule_immutable_published'], 'DET-002':['test_rule_validation','test_composite_validation'],
 'DET-005':['test_draft_does_not_alert_and_replay_is_deterministic','test_fixtures_no_side_effects_and_failed_expectation','test_composite_live_replay_and_explanation'],
 'DET-010':['test_detection_restart_exact_logical_effect'],
 'INC-002':['test_case_idempotency'], 'INC-003':['test_state_machine_version_and_reason'],
 'INC-005':['test_state_machine_version_and_reason'], 'INC-007':['test_evidence_export_and_offline_verifier'],
 'RSP-001':['test_no_arbitrary_command'], 'RSP-003':['test_approval_quorum_and_no_execution'],
 'RSP-005':['test_expired_approval'], 'RSP-010':['test_approval_quorum_and_no_execution'],
 'INT-001':['test_contract_routes'], 'INT-005':['test_search_cursor_and_filter'],
 'INT-006':['test_error_contract_and_no_stacktrace'], 'OPS-005':['test_backup_restores_cases_and_evidence'],
 'GOV-001':['test_role_denial_audited'], 'GOV-002':['test_audit_tamper_and_truncation'],
 'GOV-003':['test_evidence_export_and_offline_verifier'],
 'EVD-001':['test_evidence_export_and_offline_verifier'], 'EVD-002':['test_tampered_payload_and_metadata'],
 'EVD-003':['test_audit_tamper_and_truncation'], 'EVD-007':['test_evidence_export_and_offline_verifier'],
 'SCA-003':['test_10000_scoped_reads'], 'SCA-006':['test_csrf','test_cookie_security_and_csp'],
 'SCA-008':['test_error_contract_and_no_stacktrace'],
}

def build():
    source=json.loads(Path('spec/requirements-r2.json').read_text(encoding='utf-8'))
    records=[]
    for section in ['functional_requirements','nonfunctional_requirements']:
        for item in source[section]:
            identifier=item['id']
            records.append({'id':identifier,'status':'partial_lab' if identifier in PARTIAL else 'not_implemented',
                            'tests':PARTIAL.get(identifier,[]), 'accepted':False})
    output={'release':'0.5.0','scope':'local-lab','full_rfp_accepted':False,'requirements':records,
            'formal_acceptance':{'passed':0,'total':len(source['acceptance_tests']),
                                 'e2e_passed':0,'e2e_total':len(source['omega_e2e'])}}
    Path('docs/acceptance/coverage.json').write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n', encoding='utf-8', newline='\n')
    lines=['# Матрица реализации 0.5.0','','`partial_lab` — проверен отдельный локальный механизм, но требование целиком не принято. '
           '`not_implemented` — реализации нет. Ни один AT или OMEGA E2E не объявлен пройденным.','',
           '| Требование | Состояние | Локальные тесты |','|---|---|---|']
    for r in records:
        lines.append('| '+r['id']+' | '+r['status']+' | '+', '.join(r['tests'])+' |')
    Path('docs/acceptance/TRACEABILITY.md').write_text('\n'.join(lines)+'\n', encoding='utf-8', newline='\n')

if __name__=='__main__':
    build()
