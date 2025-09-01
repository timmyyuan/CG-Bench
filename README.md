# CG-Bench: A Call Graph Construction Benchmark for Language Models

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Paper](https://img.shields.io/badge/Paper-PDF-red.svg)](CG_Bench_Can_Language_Models_Assist_Call_Graph_Construction_in_the_Real_World.pdf)

> **📄 Paper**: [CG-Bench: Can Language Models Assist Call Graph Construction in the Real World?](CG_Bench_Can_Language_Models_Assist_Call_Graph_Construction_in_the_Real_World.pdf) - Published at LMPL@SPLASH2025

CG-Bench is a comprehensive benchmark dataset designed to evaluate the capabilities of Large Language Models (LLMs) in assisting with call graph construction in real-world C/C++ codebases. The benchmark focuses specifically on challenging indirect function calls through function pointers, which are notoriously difficult for traditional static analysis tools to resolve.

## 📋 Overview

Call graph construction is a fundamental program analysis technique crucial for various software engineering tasks including debugging, optimization, security analysis, and program comprehension. While direct function calls are straightforward to analyze, indirect calls through function pointers present significant challenges for automated tools.

This benchmark provides:
- **Real-world complexity**: Examples extracted from popular open-source projects
- **Diverse patterns**: Multiple categories of function pointer usage patterns
- **Structured format**: Consistent annotation format for evaluation
- **Comprehensive coverage**: 46 examples across 7 major open-source projects

## 🗂️ Dataset Structure

### Projects Included
The benchmark includes examples from seven major C/C++ projects:

| Project | Domain | Lines of Code | Description |
|---------|--------|---------------|-------------|
| **curl-8.5.0** | Networking | ~293K | Command line tool and library for transferring data |
| **openssh-9.6p1** | Security | ~161K | Secure Shell (SSH) protocol implementation |
| **redis-stable** | Database | - | In-memory data structure store |
| **gcc-13.2.0** | Compiler | - | GNU Compiler Collection |
| **ffmpeg** | Multimedia | - | Complete multimedia framework |
| **wrk-4.2.0** | Benchmarking | - | HTTP benchmarking tool |
| **zfs** | File System | - | ZFS file system implementation |

### Function Pointer Categories

The benchmark categorizes function pointer usage patterns into 10 distinct types:

1. **`fnptr-only`** (6 examples): Basic function pointer calls without complex patterns
2. **`fnptr-callback`** (7 examples): Function pointers used as callbacks
3. **`fnptr-struct`** (5 examples): Function pointers stored in structures
4. **`fnptr-global-array`** (3 examples): Function pointers in global arrays
5. **`fnptr-global-struct`** (5 examples): Function pointers in global structures
6. **`fnptr-global-struct-array`** (5 examples): Function pointers in arrays within global structures
7. **`fnptr-library`** (5 examples): Function pointers in library interfaces
8. **`fnptr-cast`** (4 examples): Function pointers with type casting
9. **`fnptr-dynamic-call`** (4 examples): Dynamically resolved function calls
10. **`fnptr-virtual`** (1 example): Virtual function-like patterns in C
11. **`fnptr-varargs`** (1 example): Function pointers with variable arguments

## 📁 Repository Contents

```
CG-Bench/
├── README.md                          # This file
├── LICENSE                           # MIT License
├── projects.md                       # Detailed project statistics
├── extract_from_markdowns.py         # Data extraction script
├── fnptr-*.md                        # Category-specific examples
└── CG_Bench_Can_Language_Models_Assist_Call_Graph_Construction_in_the_Real_World.pdf
```

### Example Format

Each example follows a consistent structure:

```markdown
# Example N

## Callsite
*Full path and location of the function pointer call*

fnptr: *function_pointer_name*
targets: target_function1, target_function2, ...

## Related Code Snippets
```c
// Relevant code context showing the function pointer usage
```

## 🚀 Usage

### Extracting Benchmark Data

To generate a structured JSON dataset from the markdown files:

```bash
python3 extract_from_markdowns.py
```

This creates `cgbench.json` containing all examples in a structured format suitable for evaluation.

### Data Format

The generated JSON follows this structure:

```json
{
  "project_name": {
    "callsite_path": {
      "callsite": "function_pointer_name",
      "type": "category",
      "chain_summary": [
        {
          "source_code": ["line1", "line2", ...],
          "parent": ""
        }
      ],
      "callees": {
        "targets": {
          "target_function": ""
        }
      }
    }
  }
}
```

## 📊 Benchmark Statistics

- **Total Examples**: 70
- **Project Categories**: 7 major open-source projects
- **Function Pointer Patterns**: 11 distinct categories
- **Code Contexts**: Multiple code snippets per example showing usage patterns
- **Real-world Complexity**: Examples from production codebases

## 🎯 Use Cases

This benchmark is designed for:

1. **LLM Evaluation**: Assessing language models' ability to understand complex code patterns
2. **Tool Development**: Benchmarking static analysis tools for call graph construction
3. **Research**: Studying function pointer resolution in real-world codebases
4. **Education**: Understanding various function pointer usage patterns in C/C++

## 📖 Paper Reference

This benchmark accompanies the research paper:
**"CG-Bench: Can Language Models Assist Call Graph Construction in the Real World?"**

The paper provides detailed methodology, evaluation results, and analysis of LLM performance on call graph construction tasks.

## 🤝 Contributing

We welcome contributions to expand the benchmark! Please consider:

- Adding examples from additional open-source projects
- Identifying new function pointer usage patterns
- Improving the extraction and annotation process
- Reporting issues or inconsistencies

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Citation

If you use this benchmark in your research, please cite:

```bibtex
@inproceedings{cgbench2025,
  title={CG-Bench: Can Language Models Assist Call Graph Construction in the Real World?},
  author={[Authors]},
  booktitle={Proceedings of the 1st ACM SIGPLAN International Workshop on Language Models for Programming (LMPL 2025)},
  year={2025},
  publisher={ACM},
  address={New York, NY, USA},
  url={https://conf.researchr.org/home/icfp-splash-2025/lmpl-2025},
  note={Co-located with SPLASH 2025}
}
```

## 📞 Contact

For questions or collaboration opportunities, please open an issue on GitHub or contact the maintainers.

---

**Keywords**: Call Graph Construction, Function Pointers, Static Analysis, Large Language Models, C/C++ Analysis, Software Engineering, Program Analysis

