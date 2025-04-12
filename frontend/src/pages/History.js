import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";

import {
  Box,
  Container,
  Heading,
  Text,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Button,
  Badge,
  Flex,
  Spinner,
  Alert,
  AlertIcon,
  TableContainer,
  useColorModeValue,
  ButtonGroup,
  IconButton,
  Input,
  InputGroup,
  InputLeftElement,
  HStack,
  Select,
  Pagination,
  PaginationContainer,
  PaginationPrevious,
  PaginationNext,
  PaginationPageGroup,
  PaginationPage,
} from "@chakra-ui/react";
import { ViewIcon, DownloadIcon, SearchIcon } from "@chakra-ui/icons";
import { getAnalysisHistory } from "../utils/api";

// Mock data for history (in a real app, this would come from the API)
const mockHistoryData = [
  {
    id: "1234abcd",
    file_name: "sample1.exe",
    file_type: "exe",
    upload_time: "2023-03-01T14:30:45Z",
    status: "completed",
    malware_score: 0.89,
    severity: "high",
    malware_category: "trojan",
  },
  {
    id: "5678efgh",
    file_name: "document.pdf",
    file_type: "pdf",
    upload_time: "2023-03-01T10:15:22Z",
    status: "completed",
    malware_score: 0.05,
    severity: "clean",
    malware_category: "clean",
  },
  {
    id: "9012ijkl",
    file_name: "suspicious.exe",
    file_type: "exe",
    upload_time: "2023-02-28T18:45:30Z",
    status: "completed",
    malware_score: 0.45,
    severity: "medium",
    malware_category: "adware",
  },
  {
    id: "3456mnop",
    file_name: "test_file.exe",
    file_type: "exe",
    upload_time: "2023-02-28T09:20:15Z",
    status: "failed",
    malware_score: null,
    severity: null,
    malware_category: null,
  },
  {
    id: "7890qrst",
    file_name: "report.pdf",
    file_type: "pdf",
    upload_time: "2023-02-27T16:10:05Z",
    status: "completed",
    malware_score: 0.75,
    severity: "high",
    malware_category: "backdoor",
  },
];

const severityColors = {
  high: "red",
  medium: "orange",
  low: "blue",
  clean: "green",
  unknown: "gray",
};

const statusColors = {
  completed: "green",
  processing: "blue",
  queued: "yellow",
  failed: "red",
};

const History = () => {
  const navigate = useNavigate();
  const [analyses, setAnalyses] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");

  const bg = useColorModeValue("white", "gray.800");

  // Pagination settings
  const { currentPage, setCurrentPage, pagesCount, pages } = {
    //removed usePagination
    total: analyses.length,
    limits: {
      outer: 2,
      inner: 2,
    },
    initialState: {
      pageSize: 10,
      currentPage: 1,
    },
  };

  // Fetch history data
  useEffect(() => {
    const fetchHistory = async () => {
      setIsLoading(true);
      try {
        // In a real app, this would be an API call
        // const response = await getAnalysisHistory();
        // setAnalyses(response.items);

        // Using mock data for this example
        setTimeout(() => {
          setAnalyses(mockHistoryData);
          setIsLoading(false);
        }, 1000);
      } catch (error) {
        console.error("Error fetching history:", error);
        setError("Failed to load analysis history. Please try again.");
        setIsLoading(false);
      }
    };

    fetchHistory();
  }, []);

  // Handle view analysis
  const handleView = (id) => {
    navigate(`/analysis/${id}`);
  };

  // Handle download report
  const handleDownload = (id, format = "pdf") => {
    window.open(`/api/reports/${id}?format=${format}`, "_blank");
  };

  // Filter analyses based on search and filters
  const filteredAnalyses = analyses.filter((analysis) => {
    const matchesSearch = analysis.file_name
      .toLowerCase()
      .includes(searchTerm.toLowerCase());
    const matchesType =
      filterType === "all" || analysis.file_type === filterType;
    const matchesStatus =
      filterStatus === "all" || analysis.status === filterStatus;

    return matchesSearch && matchesType && matchesStatus;
  });

  // Paginate filtered analyses
  const startIdx = (currentPage - 1) * 10;
  const endIdx = startIdx + 10;
  const paginatedAnalyses = filteredAnalyses.slice(startIdx, endIdx);

  // Format date
  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  if (isLoading) {
    return (
      <Container maxW="container.xl" py={8}>
        <Flex direction="column" align="center" justify="center" h="60vh">
          <Spinner
            thickness="4px"
            speed="0.65s"
            emptyColor="gray.200"
            color="brand.500"
            size="xl"
            mb={4}
          />
          <Heading size="lg">Loading Analysis History...</Heading>
        </Flex>
      </Container>
    );
  }

  if (error) {
    return (
      <Container maxW="container.xl" py={8}>
        <Alert status="error" borderRadius="md">
          <AlertIcon />
          {error}
        </Alert>
      </Container>
    );
  }

  return (
    <Container maxW="container.xl" py={8}>
      <Box mb={6}>
        <Heading as="h1" size="xl" mb={2}>
          Analysis History
        </Heading>
        <Text color="gray.500">View and manage your past file analyses</Text>
      </Box>

      {/* Filters and search */}
      <Box mb={6}>
        <HStack spacing={4} wrap="wrap">
          <InputGroup maxW="300px">
            <InputLeftElement pointerEvents="none">
              <SearchIcon color="gray.300" />
            </InputLeftElement>
            <Input
              placeholder="Search by filename"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </InputGroup>

          <Select
            maxW="200px"
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
          >
            <option value="all">All File Types</option>
            <option value="exe">EXE Files</option>
            <option value="pdf">PDF Files</option>
          </Select>

          <Select
            maxW="200px"
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
          >
            <option value="all">All Statuses</option>
            <option value="completed">Completed</option>
            <option value="processing">Processing</option>
            <option value="queued">Queued</option>
            <option value="failed">Failed</option>
          </Select>
        </HStack>
      </Box>

      {/* Analysis history table */}
      <Box
        p={5}
        shadow="md"
        borderWidth="1px"
        borderRadius="lg"
        bg={bg}
        overflow="hidden"
        mb={6}
      >
        {filteredAnalyses.length > 0 ? (
          <TableContainer>
            <Table variant="simple">
              <Thead>
                <Tr>
                  <Th>File Name</Th>
                  <Th>Type</Th>
                  <Th>Upload Time</Th>
                  <Th>Status</Th>
                  <Th>Risk Level</Th>
                  <Th>Score</Th>
                  <Th>Actions</Th>
                </Tr>
              </Thead>
              <Tbody>
                {paginatedAnalyses.map((analysis) => (
                  <Tr key={analysis.id}>
                    <Td fontWeight="medium">{analysis.file_name}</Td>
                    <Td>
                      <Badge>{analysis.file_type.toUpperCase()}</Badge>
                    </Td>
                    <Td>{formatDate(analysis.upload_time)}</Td>
                    <Td>
                      <Badge colorScheme={statusColors[analysis.status]}>
                        {analysis.status}
                      </Badge>
                    </Td>
                    <Td>
                      {analysis.severity ? (
                        <Badge colorScheme={severityColors[analysis.severity]}>
                          {analysis.severity}
                        </Badge>
                      ) : (
                        "-"
                      )}
                    </Td>
                    <Td>
                      {analysis.malware_score !== null
                        ? `${(analysis.malware_score * 100).toFixed(1)}%`
                        : "-"}
                    </Td>
                    <Td>
                      <ButtonGroup size="sm" isAttached variant="outline">
                        <IconButton
                          aria-label="View analysis"
                          icon={<ViewIcon />}
                          onClick={() => handleView(analysis.id)}
                          colorScheme="brand"
                        />
                        {analysis.status === "completed" && (
                          <IconButton
                            aria-label="Download report"
                            icon={<DownloadIcon />}
                            onClick={() => handleDownload(analysis.id)}
                            colorScheme="brand"
                          />
                        )}
                      </ButtonGroup>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </TableContainer>
        ) : (
          <Box textAlign="center" py={10}>
            <Text fontSize="lg">
              No analysis history found matching your filters.
            </Text>
          </Box>
        )}
      </Box>

      {/* Pagination */}
      {filteredAnalyses.length > 0 && (
        <Flex justify="center" mt={4}>
          <ButtonGroup>
            <Button
              onClick={() => setCurrentPage(currentPage - 1)}
              isDisabled={currentPage === 1}
              colorScheme="brand"
              variant="outline"
            >
              Previous
            </Button>

            {pages.map((page) => (
              <Button
                key={page}
                onClick={() => setCurrentPage(page)}
                colorScheme="brand"
                variant={currentPage === page ? "solid" : "outline"}
              >
                {page}
              </Button>
            ))}

            <Button
              onClick={() => setCurrentPage(currentPage + 1)}
              isDisabled={currentPage === pagesCount}
              colorScheme="brand"
              variant="outline"
            >
              Next
            </Button>
          </ButtonGroup>
        </Flex>
      )}
    </Container>
  );
};

export default History;
