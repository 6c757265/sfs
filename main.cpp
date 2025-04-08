#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <ctime>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <iomanip>

//**// New globals for symlink support:
static std::filesystem::path g_srcBase;
static std::filesystem::path g_destBase;

namespace fs = std::filesystem;
using json = nlohmann::json;

// strucs
struct FileRecord {
    std::time_t lastModTime;
    std::string lastHash;
    bool tombstone; // false = file is live |  true = file was deleted
};

struct FileState {
    std::time_t modTime = 0;
    std::string hash;
    bool exists = false;
};

// ignore patterns
static std::vector<std::string> g_ignorePatterns;

// matches files relative path against a naive wildcard pattern
bool matchesPattern(const fs::path& relPath, const std::string& pattern) {
    std::string relStr = relPath.string();
    if (pattern.empty()) return false;

    // if pattern ends with '/' == directory prefix match
    if (pattern.back() == '/') {
        // rfind == 0 => prefix
        return (relStr.rfind(pattern, 0) == 0);
    }

    // if pattern starts with '*' do an ends-with check
    if (pattern.front() == '*') {
        std::string suffix = pattern.substr(1);
        if (suffix.size() > relStr.size()) return false;
        return std::equal(suffix.rbegin(), suffix.rend(), relStr.rbegin());
    }

    // do a naive substring match
    return (relStr.find(pattern) != std::string::npos);
}

// return true if a file's relative path should be ignored
bool shouldIgnore(const fs::path& relPath) {
    for (auto& pat : g_ignorePatterns) {
        if (matchesPattern(relPath, pat)) {
            return true;
        }
    }
    return false;
}

// dry run flagging
static bool g_dryRun = false;

// load ignore patterns from "ignore_patterns.txt" if present
void loadIgnorePatterns(const fs::path& ignoreFile) {
    if (!fs::exists(ignoreFile)) {
        std::cout << "No ignore_patterns.txt found, skipping ignore patterns.\n";
        return;
    }

    std::ifstream in(ignoreFile);
    if (!in.is_open()) {
        std::cerr << "Could not open ignore file: " << ignoreFile << "\n";
        return;
    }

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        // trim trailing spaces
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t')) {
            line.pop_back();
        }
        // trim leading spaces
        size_t pos = 0;
        while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) {
            pos++;
        }
        if (pos > 0 && pos < line.size()) {
            line.erase(0, pos);
        }

        if (!line.empty()) {
            g_ignorePatterns.push_back(line);
            std::cout << "Ignore pattern loaded: " << line << "\n";
        }
    }
}

// SHA256 hashing of a file
std::string sha256_file(const fs::path& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + file_path.string());
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Error initializing EVP context.");
    }

    const EVP_MD* sha256 = EVP_sha256();
    if (EVP_DigestInit_ex(ctx, sha256, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Error initializing SHA256.");
    }

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount()) {
        if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Error updating SHA256 hash.");
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Error finalizing SHA256 hash.");
    }
    EVP_MD_CTX_free(ctx);

    std::ostringstream result;
    for (unsigned int i = 0; i < hash_len; i++) {
        result << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return result.str();
}

// scan a directory, gather modTime + hash for each file
// skip files if they match ignore patterns
std::unordered_map<fs::path, FileState> scanDirectory(const fs::path& root) {
    std::unordered_map<fs::path, FileState> result;

    for (auto& p : fs::recursive_directory_iterator(root)) {
        if (!fs::is_regular_file(p)) continue;

        fs::path rel = fs::relative(p.path(), root);

        // Skip if ignore
        if (shouldIgnore(rel)) {
            continue;
        }

        FileState st;
        st.exists = true;
        st.modTime = static_cast<std::time_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                p.last_write_time().time_since_epoch()
            ).count()
        );
        st.hash = sha256_file(p.path());

        result[rel] = st;
    }
    return result;
}

// load index from JSON
std::unordered_map<fs::path, FileRecord> loadIndex(const fs::path& indexPath) {
    std::unordered_map<fs::path, FileRecord> indexMap;

    if (!fs::exists(indexPath)) {
        return indexMap; // empty
    }

    std::ifstream in(indexPath);
    if (!in.is_open()) {
        std::cerr << "Cannot open index file: " << indexPath << "\n";
        return indexMap;
    }

    json j;
    try {
        in >> j;
        for (auto& [k, v] : j["files"].items()) {
            FileRecord rec;
            rec.lastModTime = v.value("lastModTime", 0);
            rec.lastHash = v.value("hash", "");
            rec.tombstone = v.value("tombstone", false);
            indexMap[fs::path(k)] = rec;
        }
    } catch (...) {
        std::cerr << "Error parsing index JSON. Starting empty.\n";
    }
    return indexMap;
}

// save index to JSON
void saveIndex(const fs::path& indexPath, const std::unordered_map<fs::path, FileRecord>& indexMap) {
    json j;
    for (auto& [path, rec] : indexMap) {
        j["files"][path.string()] = {
            {"lastModTime", rec.lastModTime},
            {"hash",        rec.lastHash},
            {"tombstone",   rec.tombstone}
        };
    }

    if (g_dryRun) {
        std::cout << "[DRYRUN] would have saved index to: " << indexPath << "\n";
        return;
    }

    std::ofstream out(indexPath, std::ios::trunc);
    if (!out.is_open()) {
        std::cerr << "Could not write index to: " << indexPath << "\n";
        return;
    }

    out << std::setw(2) << j << std::endl;
    out.close();
}

// copy a file from src to dest removing dest if it exists first
// with DRY-RUN check
void copyFile(const fs::path& src, const fs::path& dest) {
    std::cout << "Copying file from: " << src << " to " << dest << "\n";

    if (g_dryRun) {
        std::cout << "[DRYRUN] Not actually copying.\n";
        return;
    }

    fs::create_directories(dest.parent_path());

    // versioning functionality with DRY-RUN support
    if (fs::exists(dest)) {
        fs::path versionsDir = dest.parent_path() / "Versions";
        fs::create_directories(versionsDir);
        auto timestamp = std::to_string(std::time(nullptr));
        fs::path versioned = versionsDir / (dest.filename().string() + "." + timestamp);

        if (g_dryRun) {
            std::cout << "[DRYRUN] would have moved old file from: " << dest
                      << " to: " << versioned << "\n";
        } else {
            fs::rename(dest, versioned);
            std::cout << "[VERSION] Moved old file to: " << versioned << "\n";
        }
    }

    // remove existing file to avoid filesys errors
    if (fs::exists(dest)) {
        fs::remove(dest);
    }

    fs::copy_file(src, dest); // default = fs::copy_options::none
    std::cout << "Copied from: " << src << " to " << dest << "\n";
}

// update an index entry
void updateIndexRecord(std::unordered_map<fs::path, FileRecord>& indexMap,
                       const fs::path& rel,
                       std::time_t modTime,
                       const std::string& hash,
                       bool tombstone=false)
{
    FileRecord& r = indexMap[rel];
    r.lastModTime = modTime;
    r.lastHash = hash;
    r.tombstone = tombstone;
}

// RENAME DETECTION: new function for old -> new in the same side if hash matches
// skip normal delete + create logic.
void detectRenamesInOneSide(
    const std::unordered_map<fs::path, FileState>& scan,
    std::unordered_map<fs::path, FileRecord>& indexMap,
    bool sideIsA
) {
    std::vector<fs::path> missingPaths;
    std::vector<fs::path> newPaths;

    // gather missing but not tombstoned from the index
    for (auto& [rel, rec] : indexMap) {
        if (!rec.tombstone && scan.find(rel) == scan.end()) {
            missingPaths.push_back(rel);
        }
    }

    // gather new from scan
    for (auto& [rel, st] : scan) {
        if (indexMap.find(rel) == indexMap.end()) {
            newPaths.push_back(rel);
        }
    }

    // attempt to match them by hash and modTime
    for (auto& oldPath : missingPaths) {
        auto oldRec = indexMap[oldPath];
        if (oldRec.tombstone) continue;

        for (auto& newPath : newPaths) {
            auto& newSt = scan.at(newPath);
            if (newSt.hash == oldRec.lastHash) {
                std::cout << "[RENAME DETECTED] "
                          << (sideIsA ? "src: " : "dest: ")
                          << oldPath << " => " << newPath << "\n";

                indexMap.erase(oldPath);
                FileRecord renamed = oldRec;
                renamed.lastModTime = newSt.modTime;
                indexMap[newPath] = renamed;

                newPaths.erase(std::remove(newPaths.begin(), newPaths.end(), newPath),
                               newPaths.end());
                break;
            }
        }
    }
}

void versionedDelete(const fs::path& filePath) {
    if (!fs::exists(filePath)) return;
    fs::path versionsDir = filePath.parent_path() / "Versions";
    fs::create_directories(versionsDir);
    auto timestamp = std::to_string(std::time(nullptr));
    fs::path versioned = versionsDir / (filePath.filename().string() + ".deleted." + timestamp);

    if (g_dryRun) {
        std::cout << "[DRYRUN] Would have moved file " << filePath 
                  << " to " << versioned << "\n";
    } else { 
        fs::rename(filePath, versioned);
        std::cout << "[VERSION] Moved deleted file " << filePath 
                  << " to " << versioned << "\n";
    }
}

// symlink Creation for Arbitrary Directories
void createAndUseSymlinks(fs::path& dirSrc, fs::path& dirDest) {
    fs::path linkSrc = fs::current_path() / "src_link";
    fs::path linkDest = fs::current_path() / "dest_link";

    // sreate symlink for source if it doesn't exist
    if (!fs::exists(linkSrc)) {
        try {
            fs::create_directory_symlink(dirSrc, linkSrc);
            std::cout << "[SYMLINK] Created symlink for src: " << linkSrc << " -> " << dirSrc << "\n";
        } catch (const fs::filesystem_error& e) {
            std::cerr << "Error creating src symlink: " << e.what() << "\n";
        }
    } else {
        std::cout << "[SYMLINK] Using existing src symlink: " << linkSrc << "\n";
    }

    // create symlink for destination if it not exist
    if (!fs::exists(linkDest)) {
        try {
            fs::create_directory_symlink(dirDest, linkDest);
            std::cout << "[SYMLINK] Created symlink for dest: " << linkDest << " -> " << dirDest << "\n";
        } catch (const fs::filesystem_error& e) {
            std::cerr << "Error creating dest symlink: " << e.what() << "\n";
        }
    } else {
        std::cout << "[SYMLINK] Using existing dest symlink: " << linkDest << "\n";
    }

    // update the directory variables to refer to the symlinks
    dirSrc = linkSrc;
    dirDest = linkDest;
}

// main()
int main(int argc, char** argv) {
    /*
       sfs.exe <dirSrc> <dirDest> <indexFile> [--dry-run] [--symlinks]
       iof you want to use symlinks for arbitrary directories add "--symlinks" at the end
       if you want dry-run mode add "--dry-run" at the end
    */
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0]
                  << " <dirSrc> <dirDest> <indexFile> [--dry-run] [--symlinks]\n";
        return 1;
    }

    // resolve input directories to canonical paths
    fs::path realSrc = fs::canonical(argv[1]); 
    fs::path realDest = fs::canonical(argv[2]);
    fs::path indexFile = argv[3];

    // set global base paths
    g_srcBase = realSrc; 
    g_destBase = realDest;

    // process additional flags:
    bool useSymlinks = false; 
    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--dry-run") {
            g_dryRun = true;
            std::cout << "[DRY RUN MODE ENABLED] No changes will be written.\n";
        } else if (arg == "--symlinks") {
            useSymlinks = true;
        }
    }

    // if symlinks flag is set, create and use symlinks for directories
    if (useSymlinks) {
        createAndUseSymlinks(realSrc, realDest);
    }

    // Now assign our working directories from the resolved paths (or symlink ones)
    fs::path dirA = realSrc;
    fs::path dirB = realDest;

    if (!fs::is_directory(dirA) || !fs::is_directory(dirB)) {
        std::cerr << "Both paths must be directories.\n";
        return 1;
    }

    // load ignore patterns
    loadIgnorePatterns("ignore_patterns.txt");

    // load index
    auto indexMap = loadIndex(indexFile);

    // scan each directory
    auto scanA = scanDirectory(dirA);
    auto scanB = scanDirectory(dirB);

    // detect renames in src and dest
    detectRenamesInOneSide(scanA, indexMap, true);
    detectRenamesInOneSide(scanB, indexMap, false);

    // gather all relevant paths
    std::unordered_set<fs::path> allPaths;
    for (auto& kv : indexMap) allPaths.insert(kv.first);
    for (auto& kv : scanA)     allPaths.insert(kv.first);
    for (auto& kv : scanB)     allPaths.insert(kv.first);

    // process each path
    for (auto& rel : allPaths) {
        auto itIdx = indexMap.find(rel);
        bool inIndex = (itIdx != indexMap.end());
        bool inA = (scanA.find(rel) != scanA.end());
        bool inB = (scanB.find(rel) != scanB.end());

        FileState stA = inA ? scanA[rel] : FileState{};
        FileState stB = inB ? scanB[rel] : FileState{};
        FileRecord oldRec{};
        if (inIndex) {
            oldRec = itIdx->second;
        }

        // brand-new in src and dest not in the index
        if (!inIndex && inA && inB) {
            if (stA.hash == stB.hash) {
                std::time_t chosenTime = std::max(stA.modTime, stB.modTime);
                updateIndexRecord(indexMap, rel, chosenTime, stA.hash, false);
                std::cout << "Detected new file in both src and dest (same content): " << rel << "\n";
            } else {
                fs::path conflictPath = (dirB / rel).string() + ".CONFLICT";
                if (!g_dryRun) {
                    fs::rename(dirB / rel, conflictPath);
                }
                std::cout << "Conflict: same filename added in src and dest with different content. "
                          << "Renamed dest's version to: " << conflictPath << "\n";
                copyFile(dirA / rel, dirB / rel);
                updateIndexRecord(indexMap, rel, stA.modTime, stA.hash, false);
            }
            continue;
        }

        // brand-new in src only not in dest not in the index
        if (!inIndex && inA && !inB) {
            copyFile(dirA / rel, dirB / rel);
            updateIndexRecord(indexMap, rel, stA.modTime, stA.hash, false);
            continue;
        }

        // brand-new in dest only not in src not in the index
        if (!inIndex && inB && !inA) {
            copyFile(dirB / rel, dirA / rel);
            updateIndexRecord(indexMap, rel, stB.modTime, stB.hash, false);
            continue;
        }

        if (!inIndex) {
            continue;
        }

        bool tomb = oldRec.tombstone;

        // file was live in index but missing in src
        if (!tomb && !inA && inB) {
            if (stB.modTime <= oldRec.lastModTime) {
                if (!g_dryRun) {
                    versionedDelete(dirB / rel);
                }
                updateIndexRecord(indexMap, rel, oldRec.lastModTime, oldRec.lastHash, true);
                std::cout << "Deleted " << dirB / rel << " (src deleted it)\n";
            } else {
                fs::path conflictName = (dirB / rel).string() + ".CONFLICT";
                if (!g_dryRun) {
                    fs::rename(dirB / rel, conflictName);
                }
                std::cout << "Conflict: file changed in dest while src deleted. Renamed: " 
                          << conflictName << "\n";
                updateIndexRecord(indexMap, rel, oldRec.lastModTime, oldRec.lastHash, true);
            }
            continue;
        }

        // file was live in index but missing in dest
        if (!tomb && !inB && inA) {
            if (stA.modTime <= oldRec.lastModTime) {
                if (!g_dryRun) {
                    versionedDelete(dirA / rel);
                }
                updateIndexRecord(indexMap, rel, oldRec.lastModTime, oldRec.lastHash, true);
                std::cout << "Deleted " << dirA / rel << " (dest deleted it)\n";
            } else {
                fs::path conflictName = (dirA / rel).string() + ".CONFLICT";
                if (!g_dryRun) {
                    fs::rename(dirA / rel, conflictName);
                }
                std::cout << "Conflict: file changed in src while dest deleted. Renamed: " 
                          << conflictName << "\n";
                updateIndexRecord(indexMap, rel, oldRec.lastModTime, oldRec.lastHash, true);
            }
            continue;
        }

        // oldRec.tombstone == true but file resurrected
        if (tomb && (inA || inB)) {
            if (inA && inB) {
                if (stA.modTime >= stB.modTime) {
                    copyFile(dirA / rel, dirB / rel);
                    updateIndexRecord(indexMap, rel, stA.modTime, stA.hash, false);
                } else {
                    copyFile(dirB / rel, dirA / rel);
                    updateIndexRecord(indexMap, rel, stB.modTime, stB.hash, false);
                }
            } else if (inA && !inB) {
                copyFile(dirA / rel, dirB / rel);
                updateIndexRecord(indexMap, rel, stA.modTime, stA.hash, false);
            } else if (inB && !inA) {
                copyFile(dirB / rel, dirA / rel);
                updateIndexRecord(indexMap, rel, stB.modTime, stB.hash, false);
            }
            continue;
        }

        // oldRec.tombstone == false, present in both src & dest
        if (!tomb && inA && inB) {
            bool changedA = (stA.modTime > oldRec.lastModTime) || (stA.hash != oldRec.lastHash);
            bool changedB = (stB.modTime > oldRec.lastModTime) || (stB.hash != oldRec.lastHash);

            if (changedA && !changedB) {
                copyFile(dirA / rel, dirB / rel);
                updateIndexRecord(indexMap, rel, stA.modTime, stA.hash, false);
            } else if (!changedA && changedB) {
                copyFile(dirB / rel, dirA / rel);
                updateIndexRecord(indexMap, rel, stB.modTime, stB.hash, false);
            } else if (changedA && changedB) {
                fs::path conflictName = (dirB / rel).string() + ".CONFLICT";
                if (!g_dryRun) {
                    fs::rename(dirB / rel, conflictName);
                }
                copyFile(dirA / rel, dirB / rel);
                std::cout << "Conflict: both sides changed " << rel 
                          << ". Preserved dest as " << conflictName << "\n";
                updateIndexRecord(indexMap, rel, stA.modTime, stA.hash, false);
            }
            continue;
        }
    }

    saveIndex(indexFile, indexMap);

    std::cout << "Sync completed.\n";
    return 0;
}
