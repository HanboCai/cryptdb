#include <main/sql_handler.hh>
#include <util/yield.hpp>

AbstractAnything::~AbstractAnything() {}

AbstractQueryExecutor::~AbstractQueryExecutor() {}

std::pair<AbstractQueryExecutor::ResultType, AbstractAnything *>
AbstractQueryExecutor::
next(const ResType &res, const NextParams &nparams)
{
    assert(false == this->finished);

    if (true == this->first_time) {
        genericPreamble(nparams);
        this->first_time = false;
    }

    // throwing an exception out of 'next' indicates that you will not
    // re-enter the function
    // > this makes handling the lock on onion adjustment/ddl much simpler
    try {
        const auto &output = this->nextImpl(res, nparams);
        switch (output.first) {
        case AbstractQueryExecutor::ResultType::QUERY_USE_RESULTS:
        case AbstractQueryExecutor::ResultType::RESULTS:
            this->finished = true;
            this->coRoutineEndHook();
            break;
        case AbstractQueryExecutor::ResultType::QUERY_COME_AGAIN:
            break;
        default:
            assert(false);
        }

        return output;
    } catch (...) {
        this->finished = true;
        this->coRoutineEndHook();

        throw;
    }

    assert(false);
}

void AbstractQueryExecutor::
genericPreamble(const NextParams &nparams)
{
    // We handle before any queries because a failed query
    // may stale the database during recovery and then
    // we'd have to handle there as well.
    try {
        nparams.ps.getSchemaCache().updateStaleness(
            nparams.ps.getEConn(), this->stales());
    } catch (const SchemaFailure &e) {
        FAIL_GenericPacketException("failed updating staleness");
    }

    if (this->usesEmbedded()) {
        TEST_ErrPkt(
            lowLevelSetCurrentDatabase(nparams.ps.getEConn(), nparams.default_db),
            "failed to set the embedded database to " + nparams.default_db + ";"
            " your client may be in an unrecoverable bad loop"
            " so consider restarting just the _client_. this can happen"
            " if you tell your client to connect to a database that exists"
            " but was not created through cryptdb.");
    }

    return;
}

std::pair<AbstractQueryExecutor::ResultType, AbstractAnything *> SimpleExecutor::
nextImpl(const ResType &res, const NextParams &nparams)
{
    reenter(this->corot) {
        yield return CR_QUERY_RESULTS(nparams.original_query);
    }

    assert(false);
}

std::pair<AbstractQueryExecutor::ResultType, AbstractAnything *> NoOpExecutor::
nextImpl(const ResType &res, const NextParams &nparams)
{
    reenter(this->corot) {
        yield return CR_QUERY_RESULTS("DO 0;");
    }

    assert(false);
}


