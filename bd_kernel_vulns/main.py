# from . import global_values
from BOMClass import BOM
# from . import config
from KernelSourceClass import KernelSource
from ConfigClass import Config
import sys


def main():
    conf = Config()
    conf.get_cli_args()

    conf.logger.info(f"BLACK DUCK COPYRIGHT PROCESSOR - v1.0")
    conf.logger.info(f"")

    process(conf)
    # config.check_args(args)
    
    sys.exit(0)

def process(conf):
    bom = BOM(conf)
    conf.logger.info(f"Working on project '{conf.bd_project}' version '{conf.bd_version}'")
    conf.logger.info(f"  {bom.complist.count() - bom.complist.count_ignored()} active components")

    phase2_data, phase3_data = bom.process_copyrights_async(conf)

    all_comp_ids = set(phase2_data.keys()) | set(phase3_data.keys())

    count_no_copyrights = 0
    conf.logger.info("SUMMARY")
    for comp_id in all_comp_ids:
        p2 = phase2_data.get(comp_id, [])
        p3 = phase3_data.get(comp_id, [])
        all_texts = list(dict.fromkeys(p2 + p3))  # deduplicated, order preserved

        name, version = bom.get_comp_name_version(comp_id)
        label = f"{name} {version}" if name else comp_id

        if len(all_texts) == 0:
            count_no_copyrights += 1

        if conf.report:
            conf.logger.info(f"  {label}:")
            if p2:
                conf.logger.info(f".   Alternate Origin Copyrights:")
                for c in p2:
                    conf.logger.info(f"      {c}")
            if p3:
                conf.logger.info(f".   Local Copyright Search:")
                for c in p3:
                    conf.logger.info(f"      {c}")
        else:
            conf.logger.info(f"  {label}: {len(all_texts)} Alternate Copyright(s) Identified")

    conf.logger.info(f"")
    conf.logger.info(
        f"Total: {len(all_comp_ids)} component(s) processed; "
        f"{count_no_copyrights} with no copyrights from any location"
    )

    conf.logger.info("Done")


if __name__ == '__main__':
    main()
