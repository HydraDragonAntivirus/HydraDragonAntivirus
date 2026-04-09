//yara.cpp
const char* getErrorMessage(int errorCode) {
    switch (errorCode) {
    case ERROR_SUCCESS: return "Success";
    case ERROR_INSUFFICIENT_MEMORY: return "Insufficient memory";
    case ERROR_COULD_NOT_ATTACH_TO_PROCESS: return "Could not attach to process";
    case ERROR_COULD_NOT_OPEN_FILE: return "Could not open file";
    case ERROR_COULD_NOT_MAP_FILE: return "Could not map file";
    case ERROR_INVALID_FILE: return "Invalid file";
    case ERROR_CORRUPT_FILE: return "Corrupt file";
    case ERROR_UNSUPPORTED_FILE_VERSION: return "Unsupported file version";
    case ERROR_INVALID_REGULAR_EXPRESSION: return "Invalid regular expression";
    case ERROR_INVALID_HEX_STRING: return "Invalid hex string";
    case ERROR_SYNTAX_ERROR: return "Syntax error";
    case ERROR_LOOP_NESTING_LIMIT_EXCEEDED: return "Loop nesting limit exceeded";
    case ERROR_DUPLICATED_LOOP_IDENTIFIER: return "Duplicated loop identifier";
    case ERROR_DUPLICATED_IDENTIFIER: return "Duplicated identifier";
    case ERROR_DUPLICATED_TAG_IDENTIFIER: return "Duplicated tag identifier";
    case ERROR_DUPLICATED_META_IDENTIFIER: return "Duplicated meta identifier";
    case ERROR_DUPLICATED_STRING_IDENTIFIER: return "Duplicated string identifier";
    case ERROR_UNREFERENCED_STRING: return "Unreferenced string";
    case ERROR_UNDEFINED_STRING: return "Undefined string";
    case ERROR_UNDEFINED_IDENTIFIER: return "Undefined identifier";
    case ERROR_MISPLACED_ANONYMOUS_STRING: return "Misplaced anonymous string";
    case ERROR_INCLUDES_CIRCULAR_REFERENCE: return "Includes circular reference";
    case ERROR_INCLUDE_DEPTH_EXCEEDED: return "Include depth exceeded";
    case ERROR_WRONG_TYPE: return "Wrong type";
    case ERROR_EXEC_STACK_OVERFLOW: return "Execution stack overflow";
    case ERROR_SCAN_TIMEOUT: return "Scan timeout";
    case ERROR_TOO_MANY_SCAN_THREADS: return "Too many scan threads";
    case ERROR_CALLBACK_ERROR: return "Callback error";
    case ERROR_INVALID_ARGUMENT: return "Invalid argument";
    case ERROR_TOO_MANY_MATCHES: return "Too many matches";
    case ERROR_INTERNAL_FATAL_ERROR: return "Internal fatal error";
    case ERROR_NESTED_FOR_OF_LOOP: return "Nested FOR OF loop";
    case ERROR_INVALID_FIELD_NAME: return "Invalid field name";
    case ERROR_UNKNOWN_MODULE: return "Unknown module";
    case ERROR_NOT_A_STRUCTURE: return "Not a structure";
    case ERROR_NOT_INDEXABLE: return "Not indexable";
    case ERROR_NOT_A_FUNCTION: return "Not a function";
    case ERROR_INVALID_FORMAT: return "Invalid format";
    case ERROR_TOO_MANY_ARGUMENTS: return "Too many arguments";
    case ERROR_WRONG_ARGUMENTS: return "Wrong arguments";
    case ERROR_WRONG_RETURN_TYPE: return "Wrong return type";
    case ERROR_DUPLICATED_STRUCTURE_MEMBER: return "Duplicated structure member";
    case ERROR_EMPTY_STRING: return "Empty string";
    case ERROR_DIVISION_BY_ZERO: return "Division by zero";
    case ERROR_REGULAR_EXPRESSION_TOO_LARGE: return "Regular expression too large";
    case ERROR_TOO_MANY_RE_FIBERS: return "Too many RE fibers";
    case ERROR_COULD_NOT_READ_PROCESS_MEMORY: return "Could not read process memory";
    case ERROR_INVALID_EXTERNAL_VARIABLE_TYPE: return "Invalid external variable type";
    case ERROR_REGULAR_EXPRESSION_TOO_COMPLEX: return "Regular expression too complex";
    case ERROR_INVALID_MODULE_NAME: return "Invalid module name";
    case ERROR_TOO_MANY_STRINGS: return "Too many strings";
    case ERROR_INTEGER_OVERFLOW: return "Integer overflow";
    case ERROR_CALLBACK_REQUIRED: return "Callback required";
    case ERROR_INVALID_OPERAND: return "Invalid operand";
    case ERROR_COULD_NOT_READ_FILE: return "Could not read file";
    case ERROR_DUPLICATED_EXTERNAL_VARIABLE: return "Duplicated external variable";
    case ERROR_INVALID_MODULE_DATA: return "Invalid module data";
    case ERROR_WRITING_FILE: return "Writing file error";
    case ERROR_INVALID_MODIFIER: return "Invalid modifier";
    case ERROR_DUPLICATED_MODIFIER: return "Duplicated modifier";
    case ERROR_BLOCK_NOT_READY: return "Block not ready";
    case ERROR_INVALID_PERCENTAGE: return "Invalid percentage";
    case ERROR_IDENTIFIER_MATCHES_WILDCARD: return "Identifier matches wildcard";
    case ERROR_INVALID_VALUE: return "Invalid value";
    case ERROR_TOO_SLOW_SCANNING: return "Too slow scanning";
    case ERROR_UNKNOWN_ESCAPE_SEQUENCE: return "Unknown escape sequence";
    default: return "Unknown error";
    }
}

int callbackyara(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
    WCHAR buffer[256];
    switch (message)
    {
    case CALLBACK_MSG_RULE_MATCHING:
    {
        YR_RULE* rule = (YR_RULE*)message_data;
        wsprintf(buffer, L"Rule \"%S\" is matching", rule->identifier);
        MessageBox(NULL, buffer, L"Notification", MB_OK);
        break;
    }
    case CALLBACK_MSG_RULE_NOT_MATCHING:
    {
        //YR_RULE* rule = (YR_RULE*)message_data;
        //wsprintf(buffer, L"Rule \"%S\" is not matching", rule->identifier);
        //MessageBox(NULL, buffer, L"Notification", MB_OK);
        break;
    }
    case CALLBACK_MSG_SCAN_FINISHED:
    {
        MessageBox(NULL, L"The scan has finished", L"Notification", MB_OK);
        break;
    }
    case CALLBACK_MSG_IMPORT_MODULE:
    {
       // YR_MODULE_IMPORT* mi = (YR_MODULE_IMPORT*)message_data;
        //wsprintf(buffer, L"Importing module \"%S\"", mi->module_name);
        //MessageBox(NULL, buffer, L"Notification", MB_OK);
        break;
    }
    case CALLBACK_MSG_MODULE_IMPORTED:
    {
        YR_MODULE_IMPORT* mi = (YR_MODULE_IMPORT*)message_data;
        if (mi == NULL) {
            MessageBox(NULL, L"YR_MODULE_IMPORT pointer is NULL", L"Error", MB_OK);
            break;
        }
        if (mi->module_name == NULL) {
            MessageBox(NULL, L"Module name is NULL", L"Error", MB_OK);
            break;
        }
        if (mi->module_data == NULL) {
            wsprintf(buffer, L"Failed to import module \"%S\"", mi->module_name);
            MessageBox(NULL, buffer, L"Error", MB_OK);
            break;
        }
        break;
    }
    case CALLBACK_MSG_TOO_MANY_MATCHES:
    {
        YR_STRING* string = (YR_STRING*)message_data;
        wsprintf(buffer, L"Too many matches for string \"%S\"", string->identifier);
        MessageBox(NULL, buffer, L"Notification", MB_OK);
        break;
    }
    case CALLBACK_MSG_CONSOLE_LOG:
    {
        break;
    }
    }

    return CALLBACK_CONTINUE;
}