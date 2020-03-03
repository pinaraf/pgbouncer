/*
 * Send a notification for each SET command in PostgreSQL
 *
 * 2020, Pierre Ducroquet
 */
#include "postgres.h"
#include "fmgr.h"

#include "tcop/utility.h"
#include "commands/async.h"


#define NOTIFY_PAYLOAD_MAX_LENGTH	(BLCKSZ - NAMEDATALEN - 128)


PG_MODULE_MAGIC;


static ProcessUtility_hook_type prev_utility_hook = NULL;

void _PG_init(void);
void _PG_fini(void);

static void 
notifyset_utility_hook (PlannedStmt *pstmt,
			const char *queryString, ProcessUtilityContext context,
			ParamListInfo params,
			QueryEnvironment *queryEnv,
			DestReceiver *dest, char *completionTag)
{
	char payload[NOTIFY_PAYLOAD_MAX_LENGTH];
	Node *parsetree;
	VariableSetStmt *stmt;

	parsetree = pstmt->utilityStmt;
	if (nodeTag(parsetree) == T_VariableSetStmt)
	{
		stmt = (VariableSetStmt *) parsetree;
		if (stmt->is_local)
		{
			// Ignore SET LOCAL
		}
		else if (stmt->kind == VAR_RESET_ALL)
		{
			Async_Notify("bouncer_notify_set", "RESET");
		}
		else
		{
			switch(stmt->kind)
			{
				case VAR_SET_VALUE:
				case VAR_SET_CURRENT:
					snprintf(payload, NOTIFY_PAYLOAD_MAX_LENGTH, "SET %s=%s", stmt->name, ExtractSetVariableArgs(stmt));
					Async_Notify("bouncer_notify_set", payload);
					break;
				case VAR_SET_DEFAULT:
				case VAR_RESET:
					snprintf(payload, NOTIFY_PAYLOAD_MAX_LENGTH, "RESET %s", stmt->name);
					Async_Notify("bouncer_notify_set", payload);
					break;
				default:
					// ignore multi so far.
					;
			}
		}
	}
	if (prev_utility_hook)
	{
		return prev_utility_hook(pstmt, queryString, context, params, queryEnv, dest, completionTag);
	}
	else
	{
		return standard_ProcessUtility(pstmt, queryString, context, params, queryEnv, dest, completionTag);
	}
}

void
_PG_init(void)
{
	/* Install hooks. */
	prev_utility_hook = ProcessUtility_hook;
	ProcessUtility_hook = notifyset_utility_hook;
}

void
_PG_fini(void)
{
	/* Uninstall hooks. */
	ProcessUtility_hook = prev_utility_hook;
}
