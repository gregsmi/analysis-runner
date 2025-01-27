#!/usr/bin/env python3

"""Produces a treemap visualization from disk usage summary stats."""

import argparse
import gzip
import json
import math
import logging
import re
from collections import defaultdict
import humanize
from cloudpathlib import AnyPath
import pandas as pd
import plotly.express as px

ROOT_NODE = '<root>'
DATASET_REGEX = re.compile(r'gs:\/\/cpg-([A-z0-9-]+)-(main|test)')


def main():
    """Main entrypoint."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--input',
        help='The path to the gzipped input JSON; supports cloud paths and can be specified multiple times',
        required=True,
        action='append',
    )
    parser.add_argument(
        '--output',
        help='The path to the output HTML report; supports cloud paths',
        required=True,
    )
    parser.add_argument(
        '--max-depth',
        help='Maximum folder depth to display',
        default=3,
        type=int,
    )
    parser.add_argument(
        '--group-by-dataset', help='Group buckets by the dataset', action='store_true'
    )
    args = parser.parse_args()

    logging.getLogger().setLevel(logging.INFO)

    rows = []

    def append_row(name, parent, size, num_blobs):
        rows.append(
            (
                name,
                parent,
                size,
                math.log2(size),
                humanize.naturalsize(size, binary=True),
                humanize.intcomma(num_blobs),
            )
        )

    root_size, root_blobs = 0, 0
    group_by_dataset = args.group_by_dataset
    datasets: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for input_path in args.input:
        logging.info(f'Processing {input_path}')
        with AnyPath(input_path).open('rb') as f:
            with gzip.open(f, 'rt') as gfz:
                for name, vals in json.load(gfz).items():
                    depth = name.count('/') - 1  # Don't account for gs:// scheme.
                    if depth > args.max_depth:
                        continue
                    size = vals['size']
                    if not size:
                        continue
                    num_blobs = vals['num_blobs']
                    # Strip one folder for the parent name. Map `gs://` to the
                    # predefined treemap root node label.
                    slash_index = name.rfind('/')
                    if slash_index > len('gs://'):
                        parent = name[:slash_index]
                    else:
                        root_size += size
                        root_blobs += num_blobs
                        match = DATASET_REGEX.search(name)
                        # fall back to ROOT_NODE if can't determine parent
                        dataset = match.groups()[0] if match else None
                        if dataset and group_by_dataset:
                            parent = dataset
                            datasets[dataset]['size'] += size
                            datasets[dataset]['num_blobs'] += num_blobs
                        else:
                            parent = ROOT_NODE

                    append_row(name, parent, size, num_blobs)

    for dataset, values in datasets.items():
        append_row(dataset, ROOT_NODE, values['size'], values['num_blobs'])

    # Finally, add the overall root.
    append_row(ROOT_NODE, '', root_size, root_blobs)

    df = pd.DataFrame(
        rows, columns=('name', 'parent', 'value', 'log2value', 'size', 'num_blobs')
    )

    fig = px.treemap(
        df,
        names='name',
        parents='parent',
        values='value',
        color='log2value',
        hover_name='name',
        hover_data={
            'name': False,
            'parent': False,
            'value': False,
            'log2value': False,
            'size': True,
            'num_blobs': True,
        },
        color_continuous_scale='Bluered',
        range_color=(30, 50),  # 1 GiB .. 1 PiB
    )
    fig.update_traces(root_color='lightgrey')

    logging.info(f'Writing result to {args.output}')
    fig.write_html(args.output)


if __name__ == '__main__':
    main()
