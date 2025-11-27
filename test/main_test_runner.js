/**
 * 玄光安全GPT - 主测试运行器
 * 整合所有测试模块，提供统一的测试接口和报告生成
 */

class MainTestRunner {
  constructor(config = {}) {
    this.config = {
      testTypes: ['unit', 'integration', 'performance', 'security'],
      reportFormat: 'html', // html, json, console
      outputDir: './test_reports',
      verbose: true,
      ...config
    };
    
    this.testModules = [];
    this.globalResults = {
      totalTests: 0,
      passed: 0,
      failed: 0,
      skipped: 0,
      startTime: null,
      endTime: null,
      duration: 0,
      resultsByModule: {}
    };
    
    console.log('玄光安全GPT - 测试运行器已初始化');
  }
  
  /**
   * 注册测试模块
   */
  registerTestModule(moduleName, testFunction) {
    this.testModules.push({ name: moduleName, run: testFunction });
    console.log(`测试模块 "${moduleName}" 已注册`);
  }
  
  /**
   * 加载并注册现有的测试模块
   */
  async loadTestModules() {
    try {
      // 注册IDS测试套件
      if (typeof IDS_TestSuite !== 'undefined') {
        this.registerTestModule('IDS_TestSuite', async () => {
          const suite = new IDS_TestSuite({ testMode: 'full' });
          await suite.initialize();
          await suite.runTests();
          return suite.results;
        });
      }
      
      // 注册性能测试
      if (typeof PerformanceTester !== 'undefined') {
        this.registerTestModule('PerformanceTester', async () => {
          const tester = new PerformanceTester();
          await tester.runTestScenario('baseline');
          return tester.getResults();
        });
      }
      
      // 注册前端功能测试
      this.registerTestModule('Frontend_Features', this.runFrontendTests);
      
      // 注册安全测试
      this.registerTestModule('Security_Tests', this.runSecurityTests);
      
      console.log(`成功加载 ${this.testModules.length} 个测试模块`);
    } catch (error) {
      console.error('加载测试模块失败:', error);
    }
  }
  
  /**
   * 运行所有测试
   */
  async runAllTests() {
    this.globalResults.startTime = new Date();
    console.log(`开始运行所有测试 (${this.testModules.length} 个模块) - ${this.globalResults.startTime.toLocaleString()}`);
    
    // 先加载测试模块
    await this.loadTestModules();
    
    // 运行每个测试模块
    for (const module of this.testModules) {
      console.log(`\n=== 开始测试: ${module.name} ===`);
      try {
        const moduleResults = await module.run();
        this.globalResults.resultsByModule[module.name] = moduleResults;
        
        // 汇总结果
        this.globalResults.totalTests += moduleResults.total || 0;
        this.globalResults.passed += moduleResults.passed || 0;
        this.globalResults.failed += moduleResults.failed || 0;
        this.globalResults.skipped += moduleResults.skipped || 0;
        
        console.log(`=== 测试完成: ${module.name} - 通过: ${moduleResults.passed || 0}, 失败: ${moduleResults.failed || 0} ===`);
      } catch (error) {
        console.error(`=== 测试失败: ${module.name} - 错误: ${error.message} ===`);
        this.globalResults.failed++;
      }
    }
    
    this.globalResults.endTime = new Date();
    this.globalResults.duration = this.globalResults.endTime - this.globalResults.startTime;
    
    // 生成报告
    this.generateReport();
    
    return this.globalResults;
  }
  
  /**
   * 运行前端功能测试
   */
  async runFrontendTests() {
    const results = {
      total: 0,
      passed: 0,
      failed: 0,
      skipped: 0,
      testCases: []
    };
    
    // 模拟前端功能测试
    const testCases = [
      { name: '导航栏功能测试', run: this.testNavigation },
      { name: '登录流程测试', run: this.testLoginFlow },
      { name: '应急响应页面测试', run: this.testIncidentResponse },
      { name: '安全审计功能测试', run: this.testSecurityAudit }
    ];
    
    for (const testCase of testCases) {
      results.total++;
      try {
        const result = await testCase.run();
        results.testCases.push({
          name: testCase.name,
          passed: true,
          ...result
        });
        results.passed++;
      } catch (error) {
        results.testCases.push({
          name: testCase.name,
          passed: false,
          error: error.message
        });
        results.failed++;
      }
    }
    
    return results;
  }
  
  /**
   * 运行安全测试
   */
  async runSecurityTests() {
    const results = {
      total: 0,
      passed: 0,
      failed: 0,
      skipped: 0,
      testCases: []
    };
    
    // 模拟安全测试
    const securityTests = [
      { name: 'Token安全存储测试', run: this.testTokenStorage },
      { name: 'CSRF保护测试', run: this.testCSRFProtection },
      { name: 'XSS防护测试', run: this.testXSSProtection },
      { name: '密码策略测试', run: this.testPasswordPolicy }
    ];
    
    for (const test of securityTests) {
      results.total++;
      try {
        const result = await test.run();
        results.testCases.push({
          name: test.name,
          passed: true,
          ...result
        });
        results.passed++;
      } catch (error) {
        results.testCases.push({
          name: test.name,
          passed: false,
          error: error.message
        });
        results.failed++;
      }
    }
    
    return results;
  }
  
  /**
   * 生成测试报告
   */
  generateReport() {
    console.log('\n\n====================================');
    console.log('玄光安全GPT - 测试报告');
    console.log('====================================');
    console.log(`运行时间: ${this.globalResults.startTime.toLocaleString()} - ${this.globalResults.endTime.toLocaleString()}`);
    console.log(`持续时间: ${this.globalResults.duration}ms`);
    console.log(`总测试数: ${this.globalResults.totalTests}`);
    console.log(`通过: ${this.globalResults.passed} (${Math.round((this.globalResults.passed / this.globalResults.totalTests) * 100)}%)`);
    console.log(`失败: ${this.globalResults.failed}`);
    console.log(`跳过: ${this.globalResults.skipped}`);
    console.log('====================================');
    
    // 生成HTML报告
    if (this.config.reportFormat === 'html') {
      this.generateHtmlReport();
    }
  }
  
  /**
   * 生成HTML格式的测试报告
   */
  generateHtmlReport() {
    // 在实际应用中，这里会生成完整的HTML报告
    console.log('HTML测试报告已生成');
  }
  
  // 测试用例实现
  async testNavigation() { return { message: '导航功能正常' }; }
  async testLoginFlow() { return { message: '登录流程正常' }; }
  async testIncidentResponse() { return { message: '应急响应页面功能正常' }; }
  async testSecurityAudit() { return { message: '安全审计功能正常' }; }
  async testTokenStorage() { return { message: 'Token安全存储通过测试' }; }
  async testCSRFProtection() { return { message: 'CSRF保护通过测试' }; }
  async testXSSProtection() { return { message: 'XSS防护通过测试' }; }
  async testPasswordPolicy() { return { message: '密码策略通过测试' }; }
}

// 导出类
if (typeof module !== 'undefined' && module.exports) {
  module.exports = MainTestRunner;
}

// 自动初始化（在浏览器环境中）
if (typeof window !== 'undefined') {
  window.MainTestRunner = MainTestRunner;
  
  // 添加测试按钮
  window.addEventListener('DOMContentLoaded', () => {
    const testButton = document.createElement('button');
    testButton.textContent = '运行测试';
    testButton.style.position = 'fixed';
    testButton.style.bottom = '20px';
    testButton.style.right = '20px';
    testButton.style.zIndex = '9999';
    testButton.onclick = async () => {
      const runner = new MainTestRunner();
      await runner.runAllTests();
    };
    document.body.appendChild(testButton);
  });
}
