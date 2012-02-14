#include "Core.h"
#include "Console.h"
#include "Export.h"
#include "PluginManager.h"

#include "DataDefs.h"
#include "df/ui.h"
#include "df/world.h"
#include "df/unit.h"

using std::string;
using std::vector;
using namespace DFHack;

using df::global::world;
using df::global::ui;

// dfhack interface
DFhackCExport const char * plugin_name ( void )
{
    return "fastdwarf";
}

DFhackCExport command_result plugin_shutdown ( Core * c )
{
    return CR_OK;
}

static int enable_fastdwarf;

DFhackCExport command_result plugin_onupdate ( Core * c )
{
    if (!enable_fastdwarf)
        return CR_OK;
    int32_t race = ui->race_id;
    int32_t civ = ui->civ_id;

    for (size_t i = 0; i < world->units.all.size(); i++)
    {
        df::unit *unit = world->units.all[i];

        if (unit->race == race && unit->civ_id == civ && unit->counters.job_counter > 0)
            unit->counters.job_counter = 0;
        // could also patch the unit->job.current_job->completion_timer
    }
    return CR_OK;
}

static command_result fastdwarf (Core * c, vector <string> & parameters)
{
    if (parameters.size() == 1 && (parameters[0] == "0" || parameters[0] == "1"))
    {
        if (parameters[0] == "0")
            enable_fastdwarf = 0;
        else
            enable_fastdwarf = 1;
        c->con.print("fastdwarf %sactivated.\n", (enable_fastdwarf ? "" : "de"));
    }
    else
    {
        c->con.print("Makes your minions move at ludicrous speeds.\n"
            "Activate with 'fastdwarf 1', deactivate with 'fastdwarf 0'.\n"
            "Current state: %d.\n", enable_fastdwarf);
    }

    return CR_OK;
}

DFhackCExport command_result plugin_init ( Core * c, std::vector <PluginCommand> &commands)
{
    commands.clear();

    commands.push_back(PluginCommand("fastdwarf",
        "enable/disable fastdwarf (parameter=0/1)",
        fastdwarf));

    return CR_OK;
}
